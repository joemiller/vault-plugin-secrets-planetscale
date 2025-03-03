package planetscaleapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"

	"github.com/hashicorp/go-cleanhttp"
)

const (
	DefaultBaseURL = "https://api.planetscale.com/v1"

	maxPerPage = 100
)

type API interface {
	CreatePassword(ctx context.Context, database, branch string, req *CreatePasswordRequest) (*Password, error)
	DeletePassword(ctx context.Context, database, branch, passwordID string) (int, error)
	FindPasswordByName(ctx context.Context, database, branch, name string) (*Password, error)
}

type Client struct {
	serviceTokenID string
	serviceToken   string
	orgID          string
	baseURL        string
	httpClient     *http.Client
}

func NewClient(serviceTokenID, serviceToken, orgID string, baseURL string) (*Client, error) {
	if serviceTokenID == "" || serviceToken == "" || orgID == "" {
		return nil, fmt.Errorf("service token ID, service token, and org ID are required")
	}

	if baseURL == "" {
		baseURL = DefaultBaseURL
	}

	return &Client{
		serviceTokenID: serviceTokenID,
		serviceToken:   serviceToken,
		orgID:          orgID,
		baseURL:        baseURL,
		httpClient:     cleanhttp.DefaultClient(),
	}, nil
}

// CreatePasswordRequest represents the parameters for creating a new branch password
type CreatePasswordRequest struct {
	Name    string   `json:"name,omitempty"`
	Role    string   `json:"role"`
	Replica bool     `json:"replica"`
	TTL     int      `json:"ttl,omitempty"`
	CIDRs   []string `json:"cidrs,omitempty"`
}

// Password represents a PlanetScale database branch password
type Password struct {
	ID             string         `json:"id"`
	Name           string         `json:"name"`
	Role           string         `json:"role"`
	CIDRs          []string       `json:"cidrs"`
	CreatedAt      string         `json:"created_at"`
	DeletedAt      string         `json:"deleted_at,omitempty"`
	ExpiresAt      string         `json:"expires_at,omitempty"`
	TTLSeconds     int            `json:"ttl_seconds"`
	AccessHostURL  string         `json:"access_host_url"`
	Username       string         `json:"username,omitempty"`
	Replica        bool           `json:"replica"`
	Renewable      bool           `json:"renewable"`
	PlainText      string         `json:"plain_text"`
	DatabaseBranch DatabaseBranch `json:"database_branch"`
}

// DatabaseBranch represents the branch information associated with a password
type DatabaseBranch struct {
	Name             string `json:"name"`
	ID               string `json:"id"`
	Production       bool   `json:"production"`
	AccessHostURL    string `json:"access_host_url"`
	MySQLEdgeAddress string `json:"mysql_edge_address"`
}

// ListPasswordsResponse represents the paginated response from the API
type ListPasswordsResponse struct {
	Passwords []Password `json:"data"`
	Page      int        `json:"page,omitempty"`
	NextPage  int        `json:"next_page,omitempty"`
}

// CreatePassword creates a new password for a database branch
func (c *Client) CreatePassword(ctx context.Context, database, branch string, req *CreatePasswordRequest) (*Password, error) {
	url := fmt.Sprintf("%s/organizations/%s/databases/%s/branches/%s/passwords",
		c.baseURL, c.orgID, database, branch)

	resp, err := c.doRequest(ctx, http.MethodPost, url, req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read response body: %w", err)
		}
		return nil, fmt.Errorf("%d: %s", resp.StatusCode, string(body))
	}

	var password Password
	if err := json.NewDecoder(resp.Body).Decode(&password); err != nil {
		return nil, err
	}

	return &password, nil
}

// DeletePassword deletes a password for a database branch
func (c *Client) DeletePassword(ctx context.Context, database, branch, passwordID string) (int, error) {
	url := fmt.Sprintf("%s/organizations/%s/databases/%s/branches/%s/passwords/%s",
		c.baseURL, c.orgID, database, branch, passwordID)

	resp, err := c.doRequest(ctx, http.MethodDelete, url, nil)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return resp.StatusCode, fmt.Errorf("failed to read response body: %w", err)
		}
		return resp.StatusCode, fmt.Errorf("%s", string(body))
	}

	return resp.StatusCode, nil
}

// ListPasswords lists all passwords for a database branch with pagination support
func (c *Client) ListPasswords(ctx context.Context, database, branch string, page int, perPage int) (*ListPasswordsResponse, error) {
	baseURL := fmt.Sprintf("%s/organizations/%s/databases/%s/branches/%s/passwords",
		c.baseURL, c.orgID, database, branch)

	// Build the URL with query parameters
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse URL: %w", err)
	}

	q := u.Query()
	if page != 0 {
		q.Set("page", strconv.Itoa(page))
	}
	if perPage != 0 {
		q.Set("per_page", strconv.Itoa(perPage))
	}
	u.RawQuery = q.Encode()

	resp, err := c.doRequest(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read response body: %w", err)
		}
		return nil, fmt.Errorf("%d: %s", resp.StatusCode, string(body))
	}

	var listResponse ListPasswordsResponse
	if err := json.NewDecoder(resp.Body).Decode(&listResponse); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &listResponse, nil
}

// FindPasswordByName finds a password by name for a database branch
func (c *Client) FindPasswordByName(ctx context.Context, database, branch, name string) (*Password, error) {
	page := 1
	const perPage = maxPerPage

	for {
		resp, err := c.ListPasswords(ctx, database, branch, page, perPage)
		if err != nil {
			return nil, fmt.Errorf("failed to list passwords: %w", err)
		}

		for _, password := range resp.Passwords {
			if password.Name == name {
				return &password, nil
			}
		}

		// If we're on the last page or have no results, we've checked all passwords
		if page >= resp.NextPage || len(resp.Passwords) == 0 {
			break
		}

		page++
	}

	return nil, fmt.Errorf("password with name %q not found", name)
}

// doRequest handles the HTTP request/response cycle with auth headers
func (c *Client) doRequest(ctx context.Context, method, url string, body interface{}) (*http.Response, error) {
	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request body: %w", err)
		}
		reader = bytes.NewReader(data)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, reader)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("%s:%s", c.serviceTokenID, c.serviceToken))

	return c.httpClient.Do(req)
}
