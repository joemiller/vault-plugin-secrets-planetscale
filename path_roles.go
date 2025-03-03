package planetscale

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	pathRolesHelpSyn = `
Manage roles for generating PlanetScale database branch passwords.`

	pathRolesHelpDesc = `
This path allows you to create and manage roles for the PlanetScale secrets engine.
Roles control the permissions and configuration for generating database branch passwords.
Each role is associated with a specific database and either a fixed branch or a branch pattern.

Required parameters:
* database - Target PlanetScale database name
* role - Access level (reader/writer/admin/readwriter)
* branch_pattern - Exact branch name or glob pattern (e.g. "main", "qa-*", "*"). If glob pattern is used, the branch parametereter is required during credential generation.

Optional parameters:
* ttl - Default credential lifetime (default: system default)
* max_ttl - Maximum credential lifetime (default: system default)
* replica - Whether the password is for a read replica
* cidrs - Default CIDR restrictions
* allow_cidr_override - Whether to allow CIDR overrides during credential generation (default: false)

When using 'branch', any branch parameter during credential generation will be ignored.
When using 'branch_pattern', a branch parameter is required during credential generation and must match the pattern.`
)

type planetscaleRoleEntry struct {
	Database          string        `json:"database"`
	BranchPattern     string        `json:"branch_pattern,omitempty"`
	Role              string        `json:"role"`
	TTL               time.Duration `json:"ttl"`
	MaxTTL            time.Duration `json:"max_ttl"`
	Replica           bool          `json:"replica,omitempty"`
	CIDRs             []string      `json:"cidrs,omitempty"`
	AllowCIDROverride bool          `json:"allow_cidr_override"`
}

func pathRoles(b *backend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "roles/" + framework.GenericNameRegex("name"),
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeLowerCaseString,
					Description: "Name of the role",
					Required:    true,
				},
				"database": {
					Type:        framework.TypeString,
					Description: "PlanetScale database name",
					Required:    true,
				},
				"branch_pattern": {
					Type:        framework.TypeString,
					Description: "Exact branch name or glob pattern (e.g. \"main\", \"qa-*\", \"*\"). If glob pattern is used, the branch parametereter is required during credential generation.",
					Required:    true,
				},
				"role": {
					Type:        framework.TypeString,
					Description: "Access level (reader/writer/admin/readwriter)",
					Required:    true,
					AllowedValues: []interface{}{
						"reader",
						"writer",
						"admin",
						"readwriter",
					},
				},
				"ttl": {
					Type:        framework.TypeDurationSecond,
					Description: "Default credential lifetime (default: 24h)",
				},
				"max_ttl": {
					Type:        framework.TypeDurationSecond,
					Description: "Maximum credential lifetime (default: 72h)",
				},
				"replica": {
					Type:        framework.TypeString,
					Description: "Database replica selection",
					Required:    false,
				},
				"cidrs": {
					Type:        framework.TypeCommaStringSlice,
					Description: "Default CIDR restrictions",
					Required:    false,
				},
				"allow_cidr_override": {
					Type:        framework.TypeBool,
					Description: "Whether to allow CIDR overrides during credential generation",
					Default:     false,
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathRoleRead,
				},
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.pathRoleWrite,
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathRoleWrite,
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.pathRoleDelete,
				},
			},
			ExistenceCheck:  b.existenceCheck,
			HelpSynopsis:    pathRolesHelpSyn,
			HelpDescription: pathRolesHelpDesc,
		},
	}
}

func (b *backend) pathRoleWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	if name == "" {
		return logical.ErrorResponse("missing role name"), nil
	}

	role, err := b.getRole(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}

	if role == nil {
		role = &planetscaleRoleEntry{}
	}

	if database, ok := d.GetOk("database"); ok {
		role.Database = database.(string)
	}
	if branchPattern, ok := d.GetOk("branch_pattern"); ok {
		role.BranchPattern = branchPattern.(string)
	}
	if accessRole, ok := d.GetOk("role"); ok {
		role.Role = accessRole.(string)
	}
	if ttl, ok := d.GetOk("ttl"); ok {
		role.TTL = time.Duration(ttl.(int)) * time.Second
	}
	if maxTTL, ok := d.GetOk("max_ttl"); ok {
		role.MaxTTL = time.Duration(maxTTL.(int)) * time.Second
	}
	if replica, ok := d.GetOk("replica"); ok {
		role.Replica = replica.(bool)
	}
	if cidrs, ok := d.GetOk("cidrs"); ok {
		role.CIDRs = cidrs.([]string)
	}
	if allowCIDROverride, ok := d.GetOk("allow_cidr_override"); ok {
		role.AllowCIDROverride = allowCIDROverride.(bool)
	}

	// Validate the role
	if err := validateRole(role); err != nil {
		return logical.ErrorResponse(err.Error()), nil // return validation error to user
	}

	// Store the role
	entry, err := logical.StorageEntryJSON(fmt.Sprintf("roles/%s", name), role)
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	return nil, nil
}

func (b *backend) pathRoleRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	if name == "" {
		return logical.ErrorResponse("missing role name"), nil
	}

	role, err := b.getRole(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, nil
	}

	data := map[string]interface{}{
		"database":            role.Database,
		"branch_pattern":      role.BranchPattern,
		"role":                role.Role,
		"ttl":                 int64(role.TTL.Seconds()),
		"max_ttl":             int64(role.MaxTTL.Seconds()),
		"replica":             role.Replica,
		"cidrs":               role.CIDRs,
		"allow_cidr_override": role.AllowCIDROverride,
	}

	return &logical.Response{Data: data}, nil
}

func (b *backend) pathRoleDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	if name == "" {
		return logical.ErrorResponse("missing role name"), nil
	}

	if err := req.Storage.Delete(ctx, fmt.Sprintf("roles/%s", name)); err != nil {
		return nil, fmt.Errorf("error deleting role: %w", err)
	}
	return nil, nil
}

// getRole fetches the role from storage
func (b *backend) getRole(ctx context.Context, s logical.Storage, name string) (*planetscaleRoleEntry, error) {
	entry, err := s.Get(ctx, fmt.Sprintf("roles/%s", name))
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	role := &planetscaleRoleEntry{}
	if err := entry.DecodeJSON(role); err != nil {
		return nil, err
	}

	return role, nil
}

func (b *backend) existenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	resp, err := b.pathRoleRead(ctx, req, data)
	return resp != nil && !resp.IsError(), err
}

// validateRole checks that the role parameters are valid
func validateRole(role *planetscaleRoleEntry) error {
	if role.Database == "" {
		return errors.New("database is required")
	}

	if role.BranchPattern == "" {
		return errors.New("branch_pattern is required")
	}

	// Validate role type
	if role.Role == "" {
		return errors.New("role is required")
	}
	validRoles := map[string]bool{
		"reader":     true,
		"writer":     true,
		"admin":      true,
		"readwriter": true,
	}
	if !validRoles[role.Role] {
		return fmt.Errorf("invalid role: %s", role.Role)
	}

	// Ensure TTL is not longer than MaxTTL
	if role.TTL > role.MaxTTL {
		return errors.New("ttl cannot be greater than max_ttl")
	}

	// Validate CIDRs if provided
	if len(role.CIDRs) > 0 {
		for _, cidr := range role.CIDRs {
			if err := validateCIDR(cidr); err != nil {
				return err
			}
		}
	}

	return nil
}

// validateCIDR checks if a CIDR string is valid
func validateCIDR(cidr string) error {
	_, _, err := net.ParseCIDR(cidr)
	if err != nil {
		return err
	}
	return nil
}
