package planetscale

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/joemiller/vault-plugin-secrets-planetscale/internal/planetscaleapi"
)

const (
	branchPasswordType = "planetscale-branch-password"
)

type walEntry struct {
	Name     string
	Database string
	Branch   string
	// TODO: we should probably include an expiration to avoid bad WAL entries growing unbounded, see: https://github.com/hashicorp/vault-plugin-secrets-kubernetes/blob/b763def6c2b07eeaa90d0efecb91734f90beedf8/wal.go#L67
}

func (b *backend) branchPasswords() *framework.Secret {
	return &framework.Secret{
		Type: "planetscale_credentials",
		Fields: map[string]*framework.FieldSchema{
			"id": {
				Type:        framework.TypeString,
				Description: "PlanetScale Password ID",
			},
			"name": {
				Type:        framework.TypeString,
				Description: "PlanetScale Password Name",
			},
			"database": {
				Type:        framework.TypeString,
				Description: "PlanetScale Database Name",
			},
			"branch": {
				Type:        framework.TypeString,
				Description: "PlanetScale Branch Name",
			},
		},
		Renew:  b.passwordRenew,
		Revoke: b.passwordRevoke,
	}
}

func (b *backend) passwordRevoke(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	id, ok := req.Secret.InternalData["id"].(string)
	if !ok || id == "" {
		return nil, fmt.Errorf("id not found in secret's internal data")
	}

	name, ok := req.Secret.InternalData["name"].(string)
	if !ok || name == "" {
		return nil, fmt.Errorf("name not found in secret's internal data")
	}

	database, ok := req.Secret.InternalData["database"].(string)
	if !ok || database == "" {
		return nil, fmt.Errorf("database not found in secret's internal data")
	}

	branch, ok := req.Secret.InternalData["branch"].(string)
	if !ok || branch == "" {
		return nil, fmt.Errorf("branch not found in secret's internal data")
	}

	b.Logger().Debug("passwordRevoke", "id", id, "name", name, "database", database, "branch", branch)

	if res, err := b.client.DeletePassword(ctx, database, branch, id); err != nil {
		if res == http.StatusNotFound {
			b.Logger().Debug("password not found during deletion - already deleted",
				"id", id, "name", name, "database", database, "branch", branch)
			return nil, nil
		}
		b.Logger().Error("failed to delete password", "error", err, "id", id)
		return nil, fmt.Errorf("failed to revoke password: %w", err)
	}

	return nil, nil
}

func (b *backend) passwordRenew(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	id, ok := req.Secret.InternalData["id"].(string)
	if !ok || id == "" {
		return nil, fmt.Errorf("id not found in secret's internal data")
	}

	name, ok := req.Secret.InternalData["name"].(string)
	if !ok || name == "" {
		return nil, fmt.Errorf("name not found in secret's internal data")
	}

	database, ok := req.Secret.InternalData["database"].(string)
	if !ok || database == "" {
		return nil, fmt.Errorf("database not found in secret's internal data")
	}

	branch, ok := req.Secret.InternalData["branch"].(string)
	if !ok || branch == "" {
		return nil, fmt.Errorf("branch not found in secret's internal data")
	}

	b.Logger().Debug("passwordRenew", "id", id, "name", name, "database", database, "branch", branch)

	// 2. Get the role to check TTL/max_TTL values
	roleName := req.Secret.InternalData["role_name"]
	if roleName == nil {
		// If role isn't stored in internal data, extract it from the lease_id
		leaseID := req.Secret.LeaseID
		if parts := strings.Split(leaseID, "/"); len(parts) >= 2 {
			roleName = parts[len(parts)-2]
		}
	}

	if roleName == nil {
		return nil, fmt.Errorf("role name could not be determined for renewal")
	}

	role, err := b.getRole(ctx, req.Storage, roleName.(string))
	if err != nil {
		return nil, fmt.Errorf("error retrieving role: %w", err)
	}

	if role == nil {
		return nil, fmt.Errorf("role %q not found for renewal", roleName)
	}

	// 3. Determine default and max lease times
	defaultLease, maxLease := b.getDefaultAndMaxLease()

	// If defined, credential TTL overrides default lease configuration
	if role.TTL > 0 {
		defaultLease = role.TTL
	}

	if role.MaxTTL > 0 {
		maxLease = role.MaxTTL
	}

	resp := &logical.Response{Secret: req.Secret}
	resp.Secret.TTL = defaultLease
	resp.Secret.MaxTTL = maxLease

	return resp, nil
}

func (b *backend) getDefaultAndMaxLease() (time.Duration, time.Duration) {
	maxLease := b.system.MaxLeaseTTL()
	defaultLease := b.system.DefaultLeaseTTL()

	if defaultLease > maxLease {
		maxLease = defaultLease
	}
	return defaultLease, maxLease
}

func (b *backend) createPassword(ctx context.Context, req *logical.Request, db, branch string, createReq *planetscaleapi.CreatePasswordRequest) (*planetscaleapi.Password, error) {
	// this should not happen, but guard against it just in case
	if createReq.Name == "" {
		return nil, fmt.Errorf("name is required")
	}

	walID, err := framework.PutWAL(ctx, req.Storage, branchPasswordType, &walEntry{
		Name:     createReq.Name,
		Database: db,
		Branch:   branch,
	})
	if err != nil {
		return nil, fmt.Errorf("error writing WAL entry during password create: %w", err)
	}

	password, err := b.client.CreatePassword(ctx, db, branch, createReq)
	if err != nil {
		return nil, fmt.Errorf("create password failed: %w", err)
	}

	if err := framework.DeleteWAL(ctx, req.Storage, walID); err != nil {
		return nil, fmt.Errorf("error deleting WAL entry during password create: %w", err)
	}
	return password, nil
}
