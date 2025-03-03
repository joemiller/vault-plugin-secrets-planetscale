package planetscale

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/helper/logging"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/joemiller/vault-plugin-secrets-planetscale/internal/planetscaleapi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	defaultLeaseTTLVal = time.Hour * 12
	maxLeaseTTLVal     = time.Hour * 24
)

func getTestBackend(t *testing.T, client planetscaleapi.API) (*backend, logical.Storage) {
	t.Helper()

	config := logical.TestBackendConfig()
	config.StorageView = new(logical.InmemStorage)
	config.Logger = logging.NewVaultLogger(hclog.Trace)
	config.System = &logical.StaticSystemView{
		DefaultLeaseTTLVal: defaultLeaseTTLVal,
		MaxLeaseTTLVal:     maxLeaseTTLVal,
	}

	b, err := Factory(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}

	if client != nil {
		b.(*backend).client = client
	}
	return b.(*backend), config.StorageView
}

func TestWALRollback(t *testing.T) {
	tests := []struct {
		name                   string
		walData                *walEntry
		findPasswordByNameFunc func(_ context.Context, database, branch, name string) (*planetscaleapi.Password, error)
		deletePasswordFunc     func(_ context.Context, database, branch, passwordID string) (int, error)
		expectErr              bool
		expectErrContains      string
	}{
		{
			name: "password not found - successful rollback",
			walData: &walEntry{
				Name:     "test-password",
				Database: "testdb",
				Branch:   "test-branch",
			},
			findPasswordByNameFunc: func(_ context.Context, database, branch, name string) (*planetscaleapi.Password, error) {
				return nil, fmt.Errorf("password not found")
			},
			expectErr: false,
		},
		{
			name: "password found and successfully deleted",
			walData: &walEntry{
				Name:     "test-password",
				Database: "testdb",
				Branch:   "test-branch",
			},
			findPasswordByNameFunc: func(_ context.Context, database, branch, name string) (*planetscaleapi.Password, error) {
				return &planetscaleapi.Password{
					ID:   "ps_test_id",
					Name: name,
				}, nil
			},
			deletePasswordFunc: func(_ context.Context, database, branch, passwordID string) (int, error) {
				return http.StatusOK, nil
			},
			expectErr: false,
		},
		{
			name: "password found but already deleted (404)",
			walData: &walEntry{
				Name:     "test-password",
				Database: "testdb",
				Branch:   "test-branch",
			},
			findPasswordByNameFunc: func(_ context.Context, database, branch, name string) (*planetscaleapi.Password, error) {
				return &planetscaleapi.Password{
					ID:   "ps_test_id",
					Name: name,
				}, nil
			},
			deletePasswordFunc: func(_ context.Context, database, branch, passwordID string) (int, error) {
				return http.StatusNotFound, fmt.Errorf("not found")
			},
			expectErr: false,
		},
		{
			name: "authentication error during deletion (401)",
			walData: &walEntry{
				Name:     "test-password",
				Database: "testdb",
				Branch:   "test-branch",
			},
			findPasswordByNameFunc: func(_ context.Context, database, branch, name string) (*planetscaleapi.Password, error) {
				return &planetscaleapi.Password{
					ID:   "ps_test_id",
					Name: name,
				}, nil
			},
			deletePasswordFunc: func(_ context.Context, database, branch, passwordID string) (int, error) {
				return http.StatusUnauthorized, fmt.Errorf("unauthorized")
			},
			expectErr:         true,
			expectErrContains: "authentication error",
		},
		{
			name: "server error during deletion (500)",
			walData: &walEntry{
				Name:     "test-password",
				Database: "testdb",
				Branch:   "test-branch",
			},
			findPasswordByNameFunc: func(_ context.Context, database, branch, name string) (*planetscaleapi.Password, error) {
				return &planetscaleapi.Password{
					ID:   "ps_test_id",
					Name: name,
				}, nil
			},
			deletePasswordFunc: func(_ context.Context, database, branch, passwordID string) (int, error) {
				return http.StatusInternalServerError, fmt.Errorf("server error")
			},
			expectErr:         true,
			expectErrContains: "server error",
		},
		{
			name: "other error during deletion",
			walData: &walEntry{
				Name:     "test-password",
				Database: "testdb",
				Branch:   "test-branch",
			},
			findPasswordByNameFunc: func(_ context.Context, database, branch, name string) (*planetscaleapi.Password, error) {
				return &planetscaleapi.Password{
					ID:   "ps_test_id",
					Name: name,
				}, nil
			},
			deletePasswordFunc: func(_ context.Context, database, branch, passwordID string) (int, error) {
				return 422, fmt.Errorf("unprocessable entity")
			},
			expectErr:         true,
			expectErrContains: "deletion failed",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			client := &mockPlanetScaleClient{
				FindPasswordByNameFunc: tc.findPasswordByNameFunc,
				DeletePasswordFunc:     tc.deletePasswordFunc,
			}

			b, storage := getTestBackend(t, client)

			// Create a mock request for the WAL rollback
			req := &logical.Request{
				Storage: storage,
			}

			// Marshall the WAL data
			var data map[string]interface{}
			if tc.walData != nil {
				data = map[string]interface{}{
					"Name":     tc.walData.Name,
					"Database": tc.walData.Database,
					"Branch":   tc.walData.Branch,
				}
			}

			err := b.walRollback(context.Background(), req, branchPasswordType, data)

			if tc.expectErr {
				require.Error(t, err)
				if tc.expectErrContains != "" {
					assert.Contains(t, err.Error(), tc.expectErrContains)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}
