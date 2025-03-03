package planetscale

import (
	"context"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRoles_CRUD(t *testing.T) {
	b, storage := getTestBackend(t, nil)

	t.Run("create and read role", func(t *testing.T) {
		roleData := map[string]interface{}{
			"database":            "testdb",
			"branch_pattern":      "test-*",
			"role":                "readwriter",
			"ttl":                 "1h",
			"max_ttl":             "24h",
			"cidrs":               []string{"10.0.0.0/8"},
			"allow_cidr_override": true,
		}

		req := &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "roles/testrole",
			Storage:   storage,
			Data:      roleData,
		}

		resp, err := b.HandleRequest(context.Background(), req)
		require.NoError(t, err)
		require.Nil(t, resp)

		// Verify read
		req = &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "roles/testrole",
			Storage:   storage,
		}

		resp, err = b.HandleRequest(context.Background(), req)
		require.NoError(t, err)
		require.NotNil(t, resp)

		assert.Equal(t, "testdb", resp.Data["database"])
		assert.Equal(t, "test-*", resp.Data["branch_pattern"])
		assert.Equal(t, "readwriter", resp.Data["role"])
		assert.Equal(t, []string{"10.0.0.0/8"}, resp.Data["cidrs"])
		assert.Equal(t, true, resp.Data["allow_cidr_override"])
	})

	t.Run("update existing role", func(t *testing.T) {
		roleData := map[string]interface{}{
			"database":            "testdb2",
			"branch_pattern":      "prod-*",
			"role":                "reader",
			"ttl":                 "2h",
			"max_ttl":             "48h",
			"cidrs":               []string{"172.16.0.0/12"},
			"allow_cidr_override": false,
		}

		req := &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "roles/testrole",
			Storage:   storage,
			Data:      roleData,
		}

		resp, err := b.HandleRequest(context.Background(), req)
		require.NoError(t, err)
		require.Nil(t, resp)

		// Verify update
		req = &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "roles/testrole",
			Storage:   storage,
		}

		resp, err = b.HandleRequest(context.Background(), req)
		require.NoError(t, err)
		require.NotNil(t, resp)

		assert.Equal(t, "testdb2", resp.Data["database"])
		assert.Equal(t, "prod-*", resp.Data["branch_pattern"])
		assert.Equal(t, "reader", resp.Data["role"])
		assert.Equal(t, []string{"172.16.0.0/12"}, resp.Data["cidrs"])
		assert.Equal(t, false, resp.Data["allow_cidr_override"])
	})

	t.Run("delete role", func(t *testing.T) {
		req := &logical.Request{
			Operation: logical.DeleteOperation,
			Path:      "roles/testrole",
			Storage:   storage,
		}

		resp, err := b.HandleRequest(context.Background(), req)
		require.NoError(t, err)
		require.Nil(t, resp)

		// Verify deletion
		req = &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "roles/testrole",
			Storage:   storage,
		}

		resp, err = b.HandleRequest(context.Background(), req)
		require.NoError(t, err)
		require.Nil(t, resp)
	})
}

// TestRoles_Validation tests the validation logic for creating and updating roles.
// Tests are performed through the Vault HTTP API rather than directly testing
// the validateRole() function to ensure that the validation logic is correctly
// integrated into the backend's request handling.
func TestRoles_Validation(t *testing.T) {
	b, storage := getTestBackend(t, nil)

	testCases := []struct {
		name              string
		data              map[string]interface{}
		expectErr         bool
		expectErrContains string
	}{
		{
			name: "missing database",
			data: map[string]interface{}{
				"branch_pattern": "test-*",
				"role":           "reader",
			},
			expectErr:         true,
			expectErrContains: "database is required",
		},
		{
			name: "missing branch_pattern",
			data: map[string]interface{}{
				"database": "testdb",
				"role":     "reader",
			},
			expectErr:         true,
			expectErrContains: "branch_pattern is required",
		},
		{
			name: "invalid role type",
			data: map[string]interface{}{
				"database":       "testdb",
				"branch_pattern": "test-*",
				"role":           "invalid",
			},
			expectErr:         true,
			expectErrContains: "invalid role: invalid",
		},
		{
			name: "ttl greater than max_ttl",
			data: map[string]interface{}{
				"database":       "testdb",
				"branch_pattern": "test-*",
				"role":           "reader",
				"ttl":            "48h",
				"max_ttl":        "24h",
			},
			expectErr:         true,
			expectErrContains: "ttl cannot be greater than max_ttl",
		},
		{
			name: "invalid CIDR",
			data: map[string]interface{}{
				"database":       "testdb",
				"branch_pattern": "test-*",
				"role":           "reader",
				"cidrs":          []string{"asdf"},
			},
			expectErr:         true,
			expectErrContains: "invalid CIDR address",
		},
		{
			name: "mixed valid and invalid CIDRs",
			data: map[string]interface{}{
				"database":       "testdb",
				"branch_pattern": "test-*",
				"role":           "reader",
				"cidrs":          []string{"10.0.0.0/8", "asdf"},
			},
			expectErr:         true,
			expectErrContains: "invalid CIDR address",
		},
		{
			name: "valid configuration",
			data: map[string]interface{}{
				"database":            "testdb",
				"branch_pattern":      "test-*",
				"role":                "reader",
				"ttl":                 "1h",
				"max_ttl":             "24h",
				"cidrs":               []string{"10.0.0.0/8"},
				"allow_cidr_override": true,
			},
			expectErr: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := &logical.Request{
				Operation: logical.UpdateOperation,
				Path:      "roles/testrole",
				Storage:   storage,
				Data:      tc.data,
			}

			resp, err := b.HandleRequest(context.Background(), req)
			if tc.expectErr {
				require.NotNil(t, resp)
				require.Error(t, resp.Error())
				assert.Contains(t, resp.Error().Error(), tc.expectErrContains)
			} else {
				require.NoError(t, err)
				require.Nil(t, resp)
			}
		})
	}
}
