package planetscale

import (
	"context"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfig_Create(t *testing.T) {
	b, storage := getTestBackend(t, nil)

	t.Run("create and read config", func(t *testing.T) {
		configData := map[string]interface{}{
			"service_token_id": "test_token_id",
			"service_token":    "test_token",
			"org_id":           "test_org",
		}

		req := &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "config",
			Storage:   storage,
			Data:      configData,
		}

		resp, err := b.HandleRequest(context.Background(), req)
		require.NoError(t, err)
		require.Nil(t, resp)

		// Verify read
		req = &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "config",
			Storage:   storage,
		}

		resp, err = b.HandleRequest(context.Background(), req)
		require.NoError(t, err)
		require.NotNil(t, resp)

		assert.Equal(t, "test_token_id", resp.Data["service_token_id"])
		assert.Equal(t, "test_org", resp.Data["org_id"])
		assert.NotContains(t, resp.Data, "service_token", "service_token should not be returned in read")
	})

	t.Run("delete config", func(t *testing.T) {
		req := &logical.Request{
			Operation: logical.DeleteOperation,
			Path:      "config",
			Storage:   storage,
		}

		resp, err := b.HandleRequest(context.Background(), req)
		require.NoError(t, err)
		require.Nil(t, resp)

		// Verify deletion
		req = &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "config",
			Storage:   storage,
		}

		resp, err = b.HandleRequest(context.Background(), req)
		require.NoError(t, err)
		require.Nil(t, resp)
	})
}

func TestConfig_Update(t *testing.T) {
	b, storage := getTestBackend(t, nil)

	// Write initial config
	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]interface{}{
			"service_token_id": "initial_token_id",
			"service_token":    "initial_token",
			"org_id":           "initial_org",
		},
	}

	resp, err := b.HandleRequest(context.Background(), req)
	require.NoError(t, err)
	require.Nil(t, resp)

	t.Run("update existing config", func(t *testing.T) {
		req := &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "config",
			Storage:   storage,
			Data: map[string]interface{}{
				"service_token_id": "updated_token_id",
				"service_token":    "updated_token",
				"org_id":           "updated_org",
			},
		}

		resp, err := b.HandleRequest(context.Background(), req)
		require.NoError(t, err)
		require.Nil(t, resp)

		// Verify update
		req = &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "config",
			Storage:   storage,
		}

		resp, err = b.HandleRequest(context.Background(), req)
		require.NoError(t, err)
		require.NotNil(t, resp)

		assert.Equal(t, "updated_token_id", resp.Data["service_token_id"])
		assert.Equal(t, "updated_org", resp.Data["org_id"])
		assert.NotContains(t, resp.Data, "service_token")
	})

	t.Run("partial update", func(t *testing.T) {
		req := &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "config",
			Storage:   storage,
			Data: map[string]interface{}{
				"org_id": "partial_update_org",
			},
		}

		resp, err := b.HandleRequest(context.Background(), req)
		require.Error(t, err)
		require.NotNil(t, resp)
		assert.Contains(t, resp.Error().Error(), "all fields are required")
	})
}

func TestConfig_Validation(t *testing.T) {
	b, storage := getTestBackend(t, nil)

	testCases := []struct {
		name    string
		data    map[string]interface{}
		wantErr bool
		errMsg  string
	}{
		{
			name: "missing service token id",
			data: map[string]interface{}{
				"service_token": "test_token",
				"org_id":        "test_org",
			},
			wantErr: true,
			errMsg:  "all fields are required",
		},
		{
			name: "missing service token",
			data: map[string]interface{}{
				"service_token_id": "test_token_id",
				"org_id":           "test_org",
			},
			wantErr: true,
			errMsg:  "all fields are required",
		},
		{
			name: "missing org id",
			data: map[string]interface{}{
				"service_token_id": "test_token_id",
				"service_token":    "test_token",
			},
			wantErr: true,
			errMsg:  "all fields are required",
		},
		{
			name: "empty service token id",
			data: map[string]interface{}{
				"service_token_id": "",
				"service_token":    "test_token",
				"org_id":           "test_org",
			},
			wantErr: true,
			errMsg:  "all fields are required",
		},
		{
			name: "empty service token",
			data: map[string]interface{}{
				"service_token_id": "test_token_id",
				"service_token":    "",
				"org_id":           "test_org",
			},
			wantErr: true,
			errMsg:  "all fields are required",
		},
		{
			name: "empty org id",
			data: map[string]interface{}{
				"service_token_id": "test_token_id",
				"service_token":    "test_token",
				"org_id":           "",
			},
			wantErr: true,
			errMsg:  "all fields are required",
		},
		{
			name: "valid config",
			data: map[string]interface{}{
				"service_token_id": "test_token_id",
				"service_token":    "test_token",
				"org_id":           "test_org",
			},
			wantErr: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := &logical.Request{
				Operation: logical.UpdateOperation,
				Path:      "config",
				Storage:   storage,
				Data:      tc.data,
			}

			resp, err := b.HandleRequest(context.Background(), req)
			if tc.wantErr {
				require.NotNil(t, resp)
				require.Error(t, resp.Error())
				assert.Contains(t, resp.Error().Error(), tc.errMsg)
			} else {
				require.NoError(t, err)
				require.Nil(t, resp)
			}
		})
	}
}
