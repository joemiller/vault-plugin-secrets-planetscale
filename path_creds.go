package planetscale

import (
	"context"
	"crypto/rand"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/go-secure-stdlib/strutil"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/joemiller/vault-plugin-secrets-planetscale/internal/planetscaleapi"
)

func pathCreds(b *backend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "creds/" + framework.GenericNameRegex("name"),
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeString,
					Description: "Name of the role",
					Required:    true,
				},
				"branch": {
					Type:        framework.TypeString,
					Description: "Target branch name (must match role's branch_pattern)",
					Required:    true,
				},
				"cidrs": {
					Type:        framework.TypeCommaStringSlice,
					Description: "CIDR restrictions (only if allow_cidr_override=true)",
					Required:    false,
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathCredsRead,
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathCredsRead,
				},
			},
			HelpSynopsis:    pathCredsHelpSyn,
			HelpDescription: pathCredsHelpDesc,
		},
	}
}

func (b *backend) pathCredsRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	var warnings []string

	name := d.Get("name").(string)
	requestedBranch, branchSpecified := d.GetOk("branch")
	// TODO: allow specifying ttl as long as it is lower than the role and system/mount ttl's?

	role, err := b.getRole(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return logical.ErrorResponse(fmt.Sprintf("role %q not found", name)), nil
	}

	// rules for branch name:
	// - if branch_pattern contains a wildcard, branch name is required
	// - if branch_pattern does not contain a wildcard, branch name is optional,
	//   but if set must match the role's branch_pattern
	if strings.Contains(role.BranchPattern, "*") && !branchSpecified {
		return logical.ErrorResponse("branch name is required when role branch_pattern contains wildcard"), nil
	}

	branch := role.BranchPattern
	if branchSpecified {
		branch = requestedBranch.(string)
	}
	if !strutil.GlobbedStringsMatch(role.BranchPattern, branch) {
		return logical.ErrorResponse(fmt.Sprintf("requested branch %q does not match role's branch_pattern %q", branch, role.BranchPattern)), nil
	}

	cidrs := role.CIDRs
	if requestCIDRs, ok := d.GetOk("cidrs"); ok {
		if !role.AllowCIDROverride {
			return logical.ErrorResponse("CIDR override not allowed by role"), nil
		}
		cidrs = requestCIDRs.([]string)
	}

	createReq := &planetscaleapi.CreatePasswordRequest{
		Name:    genPasswordName(branch),
		Role:    role.Role,
		CIDRs:   cidrs,
		Replica: role.Replica,
	}

	password, err := b.createPassword(ctx, req, role.Database, branch, createReq)
	if err != nil {
		return logical.ErrorResponse("create password failed: %v", err), nil
	}

	resp := b.Secret(b.branchPasswords().Type).Response(map[string]interface{}{
		"id":              password.ID,
		"name":            password.Name,
		"username":        password.Username,
		"password":        password.PlainText,
		"access_host_url": password.AccessHostURL,
		"role":            password.Role,
		"database":        role.Database,
		"branch":          branch,
	}, map[string]interface{}{
		"id":        password.ID,
		"name":      password.Name,
		"database":  role.Database,
		"branch":    branch,
		"role_name": name,
	})
	resp.Warnings = warnings

	defaultLease, maxLease := b.getDefaultAndMaxLease()

	// If defined, credential TTL overrides default lease configuration
	if role.TTL > 0 {
		defaultLease = role.TTL
	}

	if role.MaxTTL > 0 {
		maxLease = role.MaxTTL
	}

	resp.Secret.TTL = defaultLease
	resp.Secret.MaxTTL = maxLease

	return resp, nil
}

// genPasswordName generates a unique password name following the pattern:
// vault-<branch>-<timestamp>-<4random hex chars>
func genPasswordName(branch string) string {
	timestamp := time.Now().Unix()
	randomHex := make([]byte, 2) // 2 bytes = 4 hex chars
	rand.Read(randomHex)         //nolint:errcheck
	return fmt.Sprintf("vault-%s-%d-%x", branch, timestamp, randomHex)
}

const pathCredsHelpSyn = `Generate PlanetScale database credentials based on a role.`

const pathCredsHelpDesc = `
This path generates database credentials based on a role definition.
The role specifies the database, branch pattern, and access level for
the generated credentials.`
