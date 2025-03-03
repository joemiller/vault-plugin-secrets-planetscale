package planetscale

import (
	"context"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// pathRolesList returns a framework.Path for listing roles
func pathRolesList(b *backend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "roles/?$",

			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: b.pathRolesList,
				},
			},

			HelpSynopsis:    pathRolesListHelpSyn,
			HelpDescription: pathRolesListHelpDesc,
		},
	}
}

// pathRolesList handles the listing of roles
func (b *backend) pathRolesList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	entries, err := req.Storage.List(ctx, "role/")
	if err != nil {
		return nil, err
	}

	return logical.ListResponse(entries), nil
}

const (
	pathRolesListHelpSyn  = `List the existing roles in this backend`
	pathRolesListHelpDesc = `Roles will be listed by the role name.`
)
