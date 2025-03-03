package planetscale

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/joemiller/vault-plugin-secrets-planetscale/internal/planetscaleapi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreatePasswordWALHandling(t *testing.T) {
	tests := []struct {
		name               string
		database           string
		branch             string
		createRequest      *planetscaleapi.CreatePasswordRequest
		createFuncMock     func(_ context.Context, database, branch string, req *planetscaleapi.CreatePasswordRequest) (*planetscaleapi.Password, error)
		expectErr          bool
		expectErrContains  string
		checkWALEntries    bool
		expectedWALEntries int
	}{
		{
			name:     "successful password creation should remove WAL entry",
			database: "testdb",
			branch:   "test-branch",
			createRequest: &planetscaleapi.CreatePasswordRequest{
				Name:  "test-password",
				Role:  "readwriter",
				CIDRs: []string{"10.0.0.0/8"},
				TTL:   3600,
			},
			createFuncMock: func(_ context.Context, database, branch string, req *planetscaleapi.CreatePasswordRequest) (*planetscaleapi.Password, error) {
				return &planetscaleapi.Password{
					ID:            "ps_test_id",
					Name:          req.Name,
					Username:      "test_user",
					PlainText:     "test_password",
					Role:          req.Role,
					CIDRs:         req.CIDRs,
					TTLSeconds:    req.TTL,
					AccessHostURL: "test.psdb.cloud",
				}, nil
			},
			expectErr:          false,
			checkWALEntries:    true,
			expectedWALEntries: 0, // WAL entry should be cleaned up
		},
		{
			name:     "API failure should preserve WAL entry",
			database: "testdb",
			branch:   "test-branch",
			createRequest: &planetscaleapi.CreatePasswordRequest{
				Name:  "test-password-api-failure",
				Role:  "readwriter",
				CIDRs: []string{"10.0.0.0/8"},
				TTL:   3600,
			},
			createFuncMock: func(_ context.Context, database, branch string, req *planetscaleapi.CreatePasswordRequest) (*planetscaleapi.Password, error) {
				return nil, fmt.Errorf("simulated API failure")
			},
			expectErr:          true,
			expectErrContains:  "create password failed",
			checkWALEntries:    true,
			expectedWALEntries: 1, // WAL entry should be preserved
		},
		{
			name:     "empty password name should not create WAL entry",
			database: "testdb",
			branch:   "test-branch",
			createRequest: &planetscaleapi.CreatePasswordRequest{
				Name:  "", // Empty name, invalid
				Role:  "readwriter",
				CIDRs: []string{"10.0.0.0/8"},
				TTL:   3600,
			},
			expectErr:          true,
			expectErrContains:  "name is required",
			checkWALEntries:    true,
			expectedWALEntries: 0, // Should not create WAL entry for invalid request
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			client := &mockPlanetScaleClient{
				CreatePasswordFunc: tc.createFuncMock,
			}

			b, storage := getTestBackend(t, client)

			// Clear any existing WAL entries
			ctx := context.Background()
			walIDs, err := framework.ListWAL(ctx, storage)
			require.NoError(t, err)
			for _, walID := range walIDs {
				require.NoError(t, framework.DeleteWAL(ctx, storage, walID))
			}

			req := &logical.Request{
				Storage: storage,
			}

			password, err := b.createPassword(ctx, req, tc.database, tc.branch, tc.createRequest)

			if tc.expectErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.expectErrContains)
				assert.Nil(t, password)
			} else {
				require.NoError(t, err)
				require.NotNil(t, password)
			}

			// Check WAL entries if required by the test case
			if tc.checkWALEntries {
				walIDs, err := framework.ListWAL(ctx, storage)
				require.NoError(t, err)
				assert.Len(t, walIDs, tc.expectedWALEntries, "Unexpected number of WAL entries")

				// If we expect a WAL entry, verify its contents
				if tc.expectedWALEntries > 0 && len(walIDs) > 0 {
					// Print the WAL entry for debugging
					walEntry, err := framework.GetWAL(ctx, storage, walIDs[0])
					require.NoError(t, err)

					t.Logf("WAL entry data: %+v", walEntry.Data)

					// The WAL entry data should be a map containing the fields of our walEntry struct
					walData, ok := walEntry.Data.(map[string]interface{})
					require.True(t, ok, "WAL data is not a map")

					// Extract and verify each field
					name, ok := walData["Name"].(string)
					require.True(t, ok, "Name field not found or not a string")
					database, ok := walData["Database"].(string)
					require.True(t, ok, "Database field not found or not a string")
					branch, ok := walData["Branch"].(string)
					require.True(t, ok, "Branch field not found or not a string")

					assert.Equal(t, tc.createRequest.Name, name)
					assert.Equal(t, tc.database, database)
					assert.Equal(t, tc.branch, branch)
				}
			}
		})
	}
}

func TestPasswordRenew(t *testing.T) {
	tests := []struct {
		name               string
		secretInternalData map[string]interface{}
		roleData           *planetscaleRoleEntry
		roleName           string
		validateResponse   func(t *testing.T, resp *logical.Response)
	}{
		{
			name: "successful renewal with role TTL",
			secretInternalData: map[string]interface{}{
				"id":       "ps_test_id",
				"name":     "vault-test-branch-12345-ab12",
				"database": "testdb",
				"branch":   "test-branch",
				"role":     "readwriter",
			},
			roleName: "testrole",
			roleData: &planetscaleRoleEntry{
				Database:          "testdb",
				BranchPattern:     "test-*",
				Role:              "readwriter",
				TTL:               time.Hour * 2,
				MaxTTL:            time.Hour * 24,
				CIDRs:             []string{"10.0.0.0/8"},
				AllowCIDROverride: true,
			},
			validateResponse: func(t *testing.T, resp *logical.Response) {
				require.NotNil(t, resp)
				require.NotNil(t, resp.Secret)
				assert.Equal(t, time.Hour*2, resp.Secret.TTL)
				assert.Equal(t, time.Hour*24, resp.Secret.MaxTTL)
			},
		},
		{
			name: "successful renewal with default TTL",
			secretInternalData: map[string]interface{}{
				"id":       "ps_test_id",
				"name":     "vault-test-branch-12345-ab12",
				"database": "testdb",
				"branch":   "test-branch",
				"role":     "reader",
			},
			roleName: "default-ttl-role",
			roleData: &planetscaleRoleEntry{
				Database:          "testdb",
				BranchPattern:     "test-*",
				Role:              "reader",
				TTL:               0, // Use default
				MaxTTL:            0, // Use default
				CIDRs:             []string{"10.0.0.0/8"},
				AllowCIDROverride: true,
			},
			validateResponse: func(t *testing.T, resp *logical.Response) {
				require.NotNil(t, resp)
				require.NotNil(t, resp.Secret)
				assert.Equal(t, defaultLeaseTTLVal, resp.Secret.TTL)
				assert.Equal(t, maxLeaseTTLVal, resp.Secret.MaxTTL)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			b, storage := getTestBackend(t, nil)

			// Store role in storage
			entry, err := logical.StorageEntryJSON("roles/"+tc.roleName, tc.roleData)
			require.NoError(t, err)
			err = storage.Put(context.Background(), entry)
			require.NoError(t, err)

			req := &logical.Request{
				Operation: logical.RenewOperation,
				Storage:   storage,
				Secret: &logical.Secret{
					LeaseID:      "planetscale/creds/" + tc.roleName + "/abc123",
					InternalData: tc.secretInternalData,
				},
			}

			resp, err := b.passwordRenew(context.Background(), req, nil)

			require.NoError(t, err)
			tc.validateResponse(t, resp)
		})
	}
}
