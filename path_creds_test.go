package planetscale

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/joemiller/vault-plugin-secrets-planetscale/internal/planetscaleapi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockPlanetScaleClient is a mock implementation of the PlanetScale API client
type mockPlanetScaleClient struct {
	CreatePasswordFunc     func(ctx context.Context, database, branch string, req *planetscaleapi.CreatePasswordRequest) (*planetscaleapi.Password, error)
	DeletePasswordFunc     func(ctx context.Context, database, branch, passwordID string) (int, error)
	FindPasswordByNameFunc func(ctx context.Context, database, branch, name string) (*planetscaleapi.Password, error)
}

func (m *mockPlanetScaleClient) CreatePassword(ctx context.Context, database, branch string, req *planetscaleapi.CreatePasswordRequest) (*planetscaleapi.Password, error) {
	if m.CreatePasswordFunc != nil {
		return m.CreatePasswordFunc(ctx, database, branch, req)
	}
	return nil, fmt.Errorf("CreatePasswordFunc not implemented in test")
}

func (m *mockPlanetScaleClient) DeletePassword(ctx context.Context, database, branch, passwordID string) (int, error) {
	if m.DeletePasswordFunc != nil {
		return m.DeletePasswordFunc(ctx, database, branch, passwordID)
	}
	return http.StatusInternalServerError, fmt.Errorf("DeletePasswordFunc not implemented in test")
}

func (m *mockPlanetScaleClient) FindPasswordByName(ctx context.Context, database, branch, name string) (*planetscaleapi.Password, error) {
	if m.FindPasswordByNameFunc != nil {
		return m.FindPasswordByNameFunc(ctx, database, branch, name)
	}
	return nil, fmt.Errorf("FindPasswordByNameFunc not implemented in test")
}

func TestCreds(t *testing.T) {
	// setupTestEnvironment creates a test backend with a standard role
	setupTestEnvironment := func(allowCIDROverride bool) (*backend, logical.Storage, *mockPlanetScaleClient) {
		mockClient := &mockPlanetScaleClient{}

		// Default successful response if mockResponse is not set in a test case
		mockClient.CreatePasswordFunc = func(_ context.Context, database, branch string, req *planetscaleapi.CreatePasswordRequest) (*planetscaleapi.Password, error) {
			return &planetscaleapi.Password{
				ID:            "ps_test_id",
				Name:          req.Name,
				Username:      "test_user",
				PlainText:     "test_password",
				Role:          req.Role,
				CIDRs:         req.CIDRs,
				TTLSeconds:    req.TTL,
				AccessHostURL: "test.psdb.cloud",
				DatabaseBranch: planetscaleapi.DatabaseBranch{
					Name: branch,
					ID:   "test-branch-id",
				},
			}, nil
		}

		b, storage := getTestBackend(t, mockClient)

		// Create a role with glob branch pattern
		globRoleData := map[string]interface{}{
			"database":            "testdb",
			"branch_pattern":      "test-*",
			"role":                "readwriter",
			"ttl":                 "1h",
			"max_ttl":             "24h",
			"cidrs":               []string{"10.0.0.0/8"},
			"allow_cidr_override": allowCIDROverride,
		}

		req := &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "roles/glob-branch-role",
			Storage:   storage,
			Data:      globRoleData,
		}

		resp, err := b.HandleRequest(context.Background(), req)
		require.NoError(t, err)
		require.Nil(t, resp)

		// Create a role with static branch pattern
		staticRoleData := map[string]interface{}{
			"database":            "testdb",
			"branch_pattern":      "main",
			"role":                "readwriter",
			"ttl":                 "1h",
			"max_ttl":             "24h",
			"cidrs":               []string{"10.0.0.0/8"},
			"allow_cidr_override": allowCIDROverride,
		}

		req = &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "roles/static-branch-role",
			Storage:   storage,
			Data:      staticRoleData,
		}

		resp, err = b.HandleRequest(context.Background(), req)
		require.NoError(t, err)
		require.Nil(t, resp)

		return b, storage, mockClient
	}

	testCases := []struct {
		name              string
		rolePath          string
		requestData       map[string]interface{}
		allowCIDROverride bool
		// mockResponse mocks the return from the planetscale API CreatePassword call
		mockResponse *planetscaleapi.Password
		// mockError mocks the return from the planetscale API CreatePassword call
		mockError         error
		expectErr         bool
		expectErrContains string
		validateResponse  func(t *testing.T, resp *logical.Response, capturedReq *planetscaleapi.CreatePasswordRequest, capturedDB, capturedBranch string)
	}{
		{
			name:              "generates credentials successfully",
			rolePath:          "glob-branch-role",
			requestData:       map[string]interface{}{"branch": "test-branch"},
			allowCIDROverride: true,
			mockResponse: &planetscaleapi.Password{
				ID:            "ps_test_id",
				Name:          "test_password",
				Username:      "test_user",
				PlainText:     "test_password",
				Role:          "readwriter",
				CIDRs:         []string{"10.0.0.0/8"},
				AccessHostURL: "test.psdb.cloud",
				DatabaseBranch: planetscaleapi.DatabaseBranch{
					Name: "test-branch",
					ID:   "test-branch-id",
				},
			},
			expectErr: false,
			validateResponse: func(t *testing.T, resp *logical.Response, capturedReq *planetscaleapi.CreatePasswordRequest, capturedDB, capturedBranch string) {
				assert.Equal(t, "testdb", capturedDB)
				assert.Equal(t, "test-branch", capturedBranch)
				assert.Equal(t, "readwriter", capturedReq.Role)
				assert.Equal(t, []string{"10.0.0.0/8"}, capturedReq.CIDRs)

				assert.Equal(t, "ps_test_id", resp.Data["id"])
				assert.Equal(t, "test_user", resp.Data["username"])
				assert.Equal(t, "test_password", resp.Data["password"])
				assert.Equal(t, "test.psdb.cloud", resp.Data["access_host_url"])
				assert.Equal(t, "readwriter", resp.Data["role"])
				assert.Equal(t, "testdb", resp.Data["database"])
				assert.Equal(t, "test-branch", resp.Data["branch"])
			},
		},
		{
			name:              "branch validation with glob branch_pattern",
			rolePath:          "glob-branch-role",
			requestData:       map[string]interface{}{"branch": "prod-branch"}, // Doesn't match "test-*" pattern
			allowCIDROverride: true,
			expectErr:         true,
			expectErrContains: "does not match",
		},
		{
			name:              "missing branch parameter when branch_pattern is a glob",
			rolePath:          "glob-branch-role",
			requestData:       map[string]interface{}{}, // Empty/no args provided.
			allowCIDROverride: true,
			expectErr:         true,
			expectErrContains: "required",
		},
		{
			name:              "branch parameter provided when branch_pattern is a static value",
			rolePath:          "static-branch-role",
			requestData:       map[string]interface{}{"branch": "prod-branch"}, // Doesn't match 'main', will be ignored anyway
			allowCIDROverride: true,
			expectErr:         true,
			expectErrContains: "does not match role's branch_pattern",
		},
		{
			name:              "role not found",
			rolePath:          "nonexistent",
			requestData:       map[string]interface{}{"branch": "test-branch"},
			allowCIDROverride: true,
			expectErr:         true,
			expectErrContains: "not found",
		},
		{
			name:              "CIDR override allowed",
			rolePath:          "glob-branch-role",
			requestData:       map[string]interface{}{"branch": "test-branch", "cidrs": "192.168.1.0/24,192.168.2.0/24"},
			allowCIDROverride: true,
			expectErr:         false,
			validateResponse: func(t *testing.T, resp *logical.Response, capturedReq *planetscaleapi.CreatePasswordRequest, capturedDB, capturedBranch string) {
				assert.Equal(t, []string{"192.168.1.0/24", "192.168.2.0/24"}, capturedReq.CIDRs)
			},
		},
		{
			name:              "CIDR override not allowed",
			rolePath:          "glob-branch-role",
			requestData:       map[string]interface{}{"branch": "test-branch", "cidrs": "192.168.1.0/24"},
			allowCIDROverride: false,
			expectErr:         true,
			expectErrContains: "not allowed",
		},
		// TODO: allow specifying ttl as long as it is lower than the role and system/mount ttl's?
		// {
		// 	name:              "TTL handling",
		// 	rolePath:          "testrole",
		// 	requestData:       map[string]interface{}{"branch": "test-branch", "ttl": "30m"},
		// 	allowCIDROverride: true,
		// 	expectErr:       false,
		// 	validateResponse: func(t *testing.T, resp *logical.Response, capturedReq *planetscaleapi.CreatePasswordRequest, capturedDB, capturedBranch string) {
		// 		assert.Equal(t, 1800, capturedReq.TTL) // 30 minutes in seconds
		// 		require.NotNil(t, resp.Secret)
		// 		assert.InDelta(t, 1800, resp.Secret.LeaseOptions.TTL.Seconds(), 1.0)
		// 	},
		// },
		// {
		// 	name:              "TTL exceeds max_ttl",
		// 	rolePath:          "testrole",
		// 	requestData:       map[string]interface{}{"branch": "test-branch", "ttl": "48h"}, // Exceeds 24h max_ttl
		// 	allowCIDROverride: true,
		// 	expectErr:       false,
		// 	validateResponse: func(t *testing.T, resp *logical.Response, capturedReq *planetscaleapi.CreatePasswordRequest, capturedDB, capturedBranch string) {
		// 		maxTTLSeconds := 24 * 60 * 60 // 24h in seconds
		// 		assert.Equal(t, maxTTLSeconds, capturedReq.TTL)
		// 		require.NotNil(t, resp.Secret)
		// 		assert.InDelta(t, float64(maxTTLSeconds), resp.Secret.LeaseOptions.TTL.Seconds(), 1.0)
		// 	},
		// },
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			b, storage, mockClient := setupTestEnvironment(tc.allowCIDROverride)

			var capturedReq *planetscaleapi.CreatePasswordRequest
			var capturedDB, capturedBranch string

			// Setup our mocked planetscale API CreatePassword func.
			// We'll use this to capture the request data and to optionally return
			// a mocked password response or mocked error.
			mockClient.CreatePasswordFunc = func(_ context.Context, database, branch string, req *planetscaleapi.CreatePasswordRequest) (*planetscaleapi.Password, error) {
				capturedDB = database
				capturedBranch = branch
				capturedReq = req

				// Return mock error if specified
				if tc.mockError != nil {
					return nil, tc.mockError
				}

				// Return mock response if specified
				if tc.mockResponse != nil {
					return tc.mockResponse, nil
				}

				// Default response
				return &planetscaleapi.Password{
					ID:            "ps_test_id",
					Name:          req.Name,
					Username:      "test_user",
					PlainText:     "test_password",
					Role:          req.Role,
					CIDRs:         req.CIDRs,
					TTLSeconds:    req.TTL,
					AccessHostURL: "test.psdb.cloud",
					DatabaseBranch: planetscaleapi.DatabaseBranch{
						Name: branch,
						ID:   "test-branch-id",
					},
				}, nil
			}

			credReq := &logical.Request{
				Operation: logical.ReadOperation,
				Path:      "creds/" + tc.rolePath,
				Storage:   storage,
				Data:      tc.requestData,
			}

			credResp, err := b.HandleRequest(context.Background(), credReq)
			require.NoError(t, err)
			require.NotNil(t, credResp)

			if tc.expectErr {
				require.True(t, credResp.IsError())
				assert.Contains(t, credResp.Error().Error(), tc.expectErrContains)
			} else {
				require.False(t, credResp.IsError(), "Response is an error: %v", credResp.Error())
				if tc.validateResponse != nil {
					tc.validateResponse(t, credResp, capturedReq, capturedDB, capturedBranch)
				}
			}
		})
	}
}
