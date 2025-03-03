package planetscale

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/joemiller/vault-plugin-secrets-planetscale/internal/planetscaleapi"
	"github.com/mitchellh/mapstructure"
)

// const walMinRollback = 5 * time.Minute
const walMinRollback = 1 * time.Minute

type backend struct {
	*framework.Backend

	client     planetscaleapi.API
	clientLock sync.RWMutex
	lock       sync.RWMutex // TODO: should we rename this to configLock? check if that's all we're using it for and if so rename it

	system logical.SystemView
}

var _ logical.Factory = Factory

func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := Backend()
	b.system = conf.System
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

func Backend() *backend {
	var b backend

	b.Backend = &framework.Backend{
		BackendType: logical.TypeLogical,
		Help:        strings.TrimSpace(backendHelp),
		PathsSpecial: &logical.Paths{
			LocalStorage: []string{},
			SealWrapStorage: []string{
				"config",
				"role/*",
			},
		},
		Paths: framework.PathAppend(
			pathConfig(&b),
			pathRoles(&b),
			pathRolesList(&b),
			pathCreds(&b),
		),
		WALRollback:       b.walRollback,
		WALRollbackMinAge: walMinRollback,
		Secrets: []*framework.Secret{
			b.branchPasswords(),
		},
		// Clean:      b.clean,
		InitializeFunc: b.initialize,
		Invalidate:     b.invalidate,
	}

	return &b
}

func (b *backend) initializeClient(config *planetscaleConfig) error {
	if config == nil {
		b.clientLock.Lock()
		b.client = nil
		b.clientLock.Unlock()
		return nil
	}

	client, err := planetscaleapi.NewClient(config.ServiceTokenID, config.ServiceToken, config.OrgID, "")
	if err != nil {
		return err
	}

	b.clientLock.Lock()
	b.client = client
	b.clientLock.Unlock()

	return nil
}

func (b *backend) initialize(ctx context.Context, req *logical.InitializationRequest) error {
	config, err := b.getConfig(ctx, req.Storage)
	if err != nil {
		return err
	}

	// It's okay if there's no config yet
	if config == nil {
		return nil
	}

	return b.initializeClient(config)
}

func (b *backend) invalidate(ctx context.Context, key string) {
	if key == "config" {
		b.lock.Lock()
		b.client = nil
		b.lock.Unlock()
	}
}

func (b *backend) walRollback(ctx context.Context, req *logical.Request, kind string, data interface{}) error {
	b.Logger().Debug("WAL rollback initiated", "kind", kind)

	if kind != branchPasswordType {
		return fmt.Errorf("unknown WAL data kind %q", kind)
	}

	var entry walEntry
	if err := mapstructure.Decode(data, &entry); err != nil {
		b.Logger().Error("error decoding WAL data", "error", err)
		return fmt.Errorf("failed to decode WAL data: %w", err)
	}

	b.Logger().Debug("WAL rollback", "name", entry.Name, "database", entry.Database, "branch", entry.Branch)

	password, err := b.client.FindPasswordByName(ctx, entry.Database, entry.Branch, entry.Name)
	if err != nil {
		// Password not found is expected if creation failed, so we just log and continue
		b.Logger().Debug("password not found during WAL rollback, assuming already deleted", "name", entry.Name, "error", err)
		return nil
	}

	// Password found, attempt to delete it
	b.Logger().Info("deleting orphaned password during WAL rollback", "name", entry.Name, "id", password.ID)
	res, err := b.client.DeletePassword(ctx, entry.Database, entry.Branch, password.ID)
	if err != nil {
		switch res {
		case http.StatusNotFound: // 404
			b.Logger().Info("password not found during WAL rollback deletion - already deleted",
				"name", entry.Name, "id", password.ID)
			return nil

		case http.StatusUnauthorized, http.StatusForbidden: // 401, 403
			b.Logger().Error("authentication error during password deletion",
				"error", err, "name", entry.Name, "id", password.ID)
			return fmt.Errorf("authentication error during rollback: %w", err)

		case http.StatusInternalServerError: // 500
			b.Logger().Error("server error during password deletion",
				"error", err, "name", entry.Name, "id", password.ID)
			return fmt.Errorf("server error during rollback: %w", err)

		default:
			b.Logger().Error("failed to delete password during WAL rollback",
				"status_code", res, "error", err, "id", password.ID)
			return fmt.Errorf("deletion failed: %w", err)
		}
	}

	return nil
}

const backendHelp = `
The PlanetScale secrets backend provides dynamic, on-demand database credentials
for PlanetScale databases. It allows you to generate short-lived database branch
passwords with specified roles and CIDR restrictions.

After mounting this backend, configure it using the "config/" endpoints and then
create one or more roles using the "roles/" endpoints. Each role manages credentials
for a specific database and branch pattern.
`
