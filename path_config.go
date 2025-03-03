package planetscale

import (
	"context"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

type planetscaleConfig struct {
	ServiceTokenID string `json:"service_token_id"`
	ServiceToken   string `json:"service_token"`
	OrgID          string `json:"org_id"`
}

const (
	pathConfigHelpSyn = `
Configure the PlanetScale secrets engine with API credentials.`

	pathConfigHelpDesc = `
This path configures the PlanetScale secrets engine with the necessary credentials
to make API calls to PlanetScale. This endpoint must be configured with a service token,
service token ID, and organization ID before the engine can perform any operations.

The provided service token requires permissions to create and manage database branch
passwords in the specified organization.`
)

func pathConfig(b *backend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "config",
			Fields: map[string]*framework.FieldSchema{
				"service_token_id": {
					Type:        framework.TypeString,
					Required:    true,
					Description: "PlanetScale service token identifier",
				},
				"service_token": {
					Type:        framework.TypeString,
					Required:    true,
					Description: "PlanetScale service token secret",
					DisplayAttrs: &framework.DisplayAttributes{
						Sensitive: true,
					},
				},
				"org_id": {
					Type:        framework.TypeString,
					Required:    true,
					Description: "PlanetScale organization identifier",
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				// logical.CreateOperation: &framework.PathOperation{
				// 	Callback: b.pathConfigWrite,
				// },
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathConfigWrite,
				},
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathConfigRead,
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.pathConfigDelete,
				},
			},
			HelpSynopsis:    pathConfigHelpSyn,
			HelpDescription: pathConfigHelpDesc,
		},
	}
}

func (b *backend) pathConfigWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	b.lock.Lock()
	defer b.lock.Unlock()

	config := &planetscaleConfig{
		ServiceTokenID: data.Get("service_token_id").(string),
		ServiceToken:   data.Get("service_token").(string),
		OrgID:          data.Get("org_id").(string),
	}

	// Validate the configuration
	if config.ServiceTokenID == "" || config.ServiceToken == "" || config.OrgID == "" {
		return logical.ErrorResponse("all fields are required: service_token_id, service_token, org_id"),
			logical.ErrInvalidRequest
	}

	// Create a new client to test the credentials
	// client, err := planetscaleapi.NewClient(config.ServiceTokenID, config.ServiceToken, config.OrgID, "")
	// if err != nil {
	// 	return nil, fmt.Errorf("failed to create PlanetScale client: %w", err)
	// }

	// Test the credentials
	// TODO
	// if err := b.client.TestConnection(ctx); err != nil {
	// 	return nil, fmt.Errorf("failed to connect to PlanetScale: %w", err)
	// }

	// Store the configuration
	entry, err := logical.StorageEntryJSON("config", config)
	if err != nil {
		return nil, fmt.Errorf("failed to generate storage entry: %w", err)
	}

	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, fmt.Errorf("failed to write configuration: %w", err)
	}

	// init/re-init the planetscale client
	if err := b.initializeClient(config); err != nil {
		return nil, err
	}

	return nil, nil
}

func (b *backend) pathConfigRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	config, err := b.getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if config == nil {
		return nil, nil
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"service_token_id": config.ServiceTokenID,
			"org_id":           config.OrgID,
		},
	}, nil
}

func (b *backend) pathConfigDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	b.lock.Lock()
	defer b.lock.Unlock()

	if err := req.Storage.Delete(ctx, "config"); err != nil {
		return nil, fmt.Errorf("failed to delete configuration: %w", err)
	}

	b.client = nil

	return nil, nil
}

// getConfig returns the configuration if it exists
func (b *backend) getConfig(ctx context.Context, s logical.Storage) (*planetscaleConfig, error) {
	entry, err := s.Get(ctx, "config")
	if err != nil {
		return nil, fmt.Errorf("failed to read configuration: %w", err)
	}

	if entry == nil {
		return nil, nil
	}

	config := &planetscaleConfig{}
	if err := entry.DecodeJSON(config); err != nil {
		return nil, fmt.Errorf("failed to decode configuration: %w", err)
	}

	return config, nil
}
