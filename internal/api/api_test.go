package api_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/bcnelson/tailscale-acl-manager/internal/api"
	"github.com/bcnelson/tailscale-acl-manager/internal/domain"
	"github.com/bcnelson/tailscale-acl-manager/internal/service"
	"github.com/bcnelson/tailscale-acl-manager/internal/storage/memory"
)

// testServer creates a test server with in-memory storage
type testServer struct {
	handler      http.Handler
	store        *memory.Store
	bootstrapKey string
}

func newTestServer() *testServer {
	store := memory.New()
	bootstrapKey := "test-bootstrap-key"

	// Create a mock sync service that doesn't actually sync to Tailscale
	syncService := service.NewSyncService(store, nil, 5*time.Second, false)

	// OIDC disabled for tests (pass nil config and components)
	handler := api.NewRouter(store, syncService, bootstrapKey, nil, nil)

	return &testServer{
		handler:      handler,
		store:        store,
		bootstrapKey: bootstrapKey,
	}
}

func (ts *testServer) request(method, path string, body any, apiKey string) *httptest.ResponseRecorder {
	var reqBody io.Reader
	if body != nil {
		jsonBytes, _ := json.Marshal(body)
		reqBody = bytes.NewReader(jsonBytes)
	}

	req := httptest.NewRequest(method, path, reqBody)
	req.Header.Set("Content-Type", "application/json")
	if apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}

	rr := httptest.NewRecorder()
	ts.handler.ServeHTTP(rr, req)
	return rr
}

func TestHealthEndpoint(t *testing.T) {
	ts := newTestServer()

	rr := ts.request("GET", "/health", nil, "")

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
	}

	var resp map[string]string
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp["status"] != "ok" {
		t.Errorf("Expected status ok, got %s", resp["status"])
	}
}

func TestAuthRequired(t *testing.T) {
	ts := newTestServer()

	// Request without auth header
	rr := ts.request("GET", "/api/v1/stacks", nil, "")
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401, got %d", rr.Code)
	}

	// Request with invalid auth header format
	req := httptest.NewRequest("GET", "/api/v1/stacks", nil)
	req.Header.Set("Authorization", "Basic invalid")
	rr = httptest.NewRecorder()
	ts.handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401, got %d", rr.Code)
	}

	// Request with invalid API key (no keys in DB, bootstrap key disabled)
	rr = ts.request("GET", "/api/v1/stacks", nil, "invalid-key")
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401, got %d", rr.Code)
	}
}

func TestBootstrapKeyAuth(t *testing.T) {
	ts := newTestServer()

	// Bootstrap key should work when no API keys exist
	rr := ts.request("GET", "/api/v1/stacks", nil, ts.bootstrapKey)
	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200 with bootstrap key, got %d", rr.Code)
	}
}

func TestAPIKeyLifecycle(t *testing.T) {
	ts := newTestServer()

	// Create API key using bootstrap key
	createReq := domain.CreateAPIKeyRequest{Name: "Test Key"}
	rr := ts.request("POST", "/api/v1/keys", createReq, ts.bootstrapKey)
	if rr.Code != http.StatusCreated {
		t.Fatalf("Expected status 201, got %d: %s", rr.Code, rr.Body.String())
	}

	var createResp domain.CreateAPIKeyResponse
	_ = json.Unmarshal(rr.Body.Bytes(), &createResp)
	if createResp.Key == "" {
		t.Error("Expected key to be returned on creation")
	}
	if createResp.Name != "Test Key" {
		t.Errorf("Expected name 'Test Key', got '%s'", createResp.Name)
	}

	// Use the new API key
	rr = ts.request("GET", "/api/v1/stacks", nil, createResp.Key)
	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200 with new API key, got %d", rr.Code)
	}

	// List API keys
	rr = ts.request("GET", "/api/v1/keys", nil, createResp.Key)
	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
	}

	var keys []*domain.APIKey
	_ = json.Unmarshal(rr.Body.Bytes(), &keys)
	if len(keys) != 1 {
		t.Errorf("Expected 1 key, got %d", len(keys))
	}

	// Delete API key
	rr = ts.request("DELETE", "/api/v1/keys/"+createResp.ID, nil, createResp.Key)
	if rr.Code != http.StatusNoContent {
		t.Errorf("Expected status 204, got %d", rr.Code)
	}
}

func TestStackCRUD(t *testing.T) {
	ts := newTestServer()

	// Create stack
	createReq := domain.CreateStackRequest{
		Name:        "terraform-prod",
		Description: "Production Terraform stack",
		Priority:    10,
	}
	rr := ts.request("POST", "/api/v1/stacks", createReq, ts.bootstrapKey)
	if rr.Code != http.StatusCreated {
		t.Fatalf("Expected status 201, got %d: %s", rr.Code, rr.Body.String())
	}

	var stack domain.Stack
	_ = json.Unmarshal(rr.Body.Bytes(), &stack)
	if stack.Name != "terraform-prod" {
		t.Errorf("Expected name 'terraform-prod', got '%s'", stack.Name)
	}
	if stack.Priority != 10 {
		t.Errorf("Expected priority 10, got %d", stack.Priority)
	}

	// Get stack (note trailing slash for the subrouter)
	rr = ts.request("GET", "/api/v1/stacks/"+stack.ID+"/", nil, ts.bootstrapKey)
	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
	}

	// List stacks
	rr = ts.request("GET", "/api/v1/stacks", nil, ts.bootstrapKey)
	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
	}

	var stacks []*domain.Stack
	_ = json.Unmarshal(rr.Body.Bytes(), &stacks)
	if len(stacks) != 1 {
		t.Errorf("Expected 1 stack, got %d", len(stacks))
	}

	// Update stack
	newPriority := 5
	updateReq := domain.UpdateStackRequest{Priority: &newPriority}
	rr = ts.request("PUT", "/api/v1/stacks/"+stack.ID+"/", updateReq, ts.bootstrapKey)
	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
	}

	var updatedStack domain.Stack
	_ = json.Unmarshal(rr.Body.Bytes(), &updatedStack)
	if updatedStack.Priority != 5 {
		t.Errorf("Expected priority 5, got %d", updatedStack.Priority)
	}

	// Delete stack
	rr = ts.request("DELETE", "/api/v1/stacks/"+stack.ID+"/", nil, ts.bootstrapKey)
	if rr.Code != http.StatusNoContent {
		t.Errorf("Expected status 204, got %d", rr.Code)
	}

	// Verify deleted
	rr = ts.request("GET", "/api/v1/stacks/"+stack.ID+"/", nil, ts.bootstrapKey)
	if rr.Code != http.StatusNotFound {
		t.Errorf("Expected status 404, got %d", rr.Code)
	}
}

func TestGroupCRUD(t *testing.T) {
	ts := newTestServer()

	// Create stack first
	stackReq := domain.CreateStackRequest{Name: "test-stack"}
	rr := ts.request("POST", "/api/v1/stacks", stackReq, ts.bootstrapKey)
	var stack domain.Stack
	_ = json.Unmarshal(rr.Body.Bytes(), &stack)

	// Create group
	groupReq := domain.CreateGroupRequest{
		Name:    "group:developers",
		Members: []string{"user1@example.com", "user2@example.com"},
	}
	rr = ts.request("POST", "/api/v1/stacks/"+stack.ID+"/groups", groupReq, ts.bootstrapKey)
	if rr.Code != http.StatusCreated {
		t.Fatalf("Expected status 201, got %d: %s", rr.Code, rr.Body.String())
	}

	var group domain.Group
	_ = json.Unmarshal(rr.Body.Bytes(), &group)
	if group.Name != "group:developers" {
		t.Errorf("Expected name 'group:developers', got '%s'", group.Name)
	}
	if len(group.Members) != 2 {
		t.Errorf("Expected 2 members, got %d", len(group.Members))
	}

	// Get group
	rr = ts.request("GET", "/api/v1/stacks/"+stack.ID+"/groups/name/group:developers", nil, ts.bootstrapKey)
	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
	}

	// List groups
	rr = ts.request("GET", "/api/v1/stacks/"+stack.ID+"/groups", nil, ts.bootstrapKey)
	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
	}

	var groups []*domain.Group
	_ = json.Unmarshal(rr.Body.Bytes(), &groups)
	if len(groups) != 1 {
		t.Errorf("Expected 1 group, got %d", len(groups))
	}

	// Update group
	updateReq := domain.UpdateGroupRequest{
		Members: []string{"user1@example.com", "user2@example.com", "user3@example.com"},
	}
	rr = ts.request("PUT", "/api/v1/stacks/"+stack.ID+"/groups/name/group:developers", updateReq, ts.bootstrapKey)
	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
	}

	var updatedGroup domain.Group
	_ = json.Unmarshal(rr.Body.Bytes(), &updatedGroup)
	if len(updatedGroup.Members) != 3 {
		t.Errorf("Expected 3 members, got %d", len(updatedGroup.Members))
	}

	// Delete group
	rr = ts.request("DELETE", "/api/v1/stacks/"+stack.ID+"/groups/name/group:developers", nil, ts.bootstrapKey)
	if rr.Code != http.StatusNoContent {
		t.Errorf("Expected status 204, got %d", rr.Code)
	}
}

func TestACLRuleCRUD(t *testing.T) {
	ts := newTestServer()

	// Create stack first
	stackReq := domain.CreateStackRequest{Name: "test-stack"}
	rr := ts.request("POST", "/api/v1/stacks", stackReq, ts.bootstrapKey)
	var stack domain.Stack
	_ = json.Unmarshal(rr.Body.Bytes(), &stack)

	// Create ACL rule
	aclReq := domain.CreateACLRuleRequest{
		Action:       "accept",
		Sources:      []string{"group:developers"},
		Destinations: []string{"tag:server:22"},
	}
	rr = ts.request("POST", "/api/v1/stacks/"+stack.ID+"/acls", aclReq, ts.bootstrapKey)
	if rr.Code != http.StatusCreated {
		t.Fatalf("Expected status 201, got %d: %s", rr.Code, rr.Body.String())
	}

	var rule domain.ACLRule
	_ = json.Unmarshal(rr.Body.Bytes(), &rule)
	if rule.Action != "accept" {
		t.Errorf("Expected action 'accept', got '%s'", rule.Action)
	}

	// Get ACL rule
	rr = ts.request("GET", "/api/v1/stacks/"+stack.ID+"/acls/"+rule.ID, nil, ts.bootstrapKey)
	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
	}

	// List ACL rules
	rr = ts.request("GET", "/api/v1/stacks/"+stack.ID+"/acls", nil, ts.bootstrapKey)
	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
	}

	// Delete ACL rule
	rr = ts.request("DELETE", "/api/v1/stacks/"+stack.ID+"/acls/"+rule.ID, nil, ts.bootstrapKey)
	if rr.Code != http.StatusNoContent {
		t.Errorf("Expected status 204, got %d", rr.Code)
	}
}

func TestHostCRUD(t *testing.T) {
	ts := newTestServer()

	// Create stack first
	stackReq := domain.CreateStackRequest{Name: "test-stack"}
	rr := ts.request("POST", "/api/v1/stacks", stackReq, ts.bootstrapKey)
	var stack domain.Stack
	_ = json.Unmarshal(rr.Body.Bytes(), &stack)

	// Create host
	hostReq := domain.CreateHostRequest{
		Name:    "webserver",
		Address: "10.0.0.1",
	}
	rr = ts.request("POST", "/api/v1/stacks/"+stack.ID+"/hosts", hostReq, ts.bootstrapKey)
	if rr.Code != http.StatusCreated {
		t.Fatalf("Expected status 201, got %d: %s", rr.Code, rr.Body.String())
	}

	var host domain.Host
	_ = json.Unmarshal(rr.Body.Bytes(), &host)
	if host.Name != "webserver" {
		t.Errorf("Expected name 'webserver', got '%s'", host.Name)
	}
	if host.Address != "10.0.0.1" {
		t.Errorf("Expected address '10.0.0.1', got '%s'", host.Address)
	}

	// Get host
	rr = ts.request("GET", "/api/v1/stacks/"+stack.ID+"/hosts/name/webserver", nil, ts.bootstrapKey)
	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
	}

	// Update host
	updateReq := domain.UpdateHostRequest{Address: "10.0.0.2"}
	rr = ts.request("PUT", "/api/v1/stacks/"+stack.ID+"/hosts/name/webserver", updateReq, ts.bootstrapKey)
	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
	}

	var updatedHost domain.Host
	_ = json.Unmarshal(rr.Body.Bytes(), &updatedHost)
	if updatedHost.Address != "10.0.0.2" {
		t.Errorf("Expected address '10.0.0.2', got '%s'", updatedHost.Address)
	}

	// Delete host
	rr = ts.request("DELETE", "/api/v1/stacks/"+stack.ID+"/hosts/name/webserver", nil, ts.bootstrapKey)
	if rr.Code != http.StatusNoContent {
		t.Errorf("Expected status 204, got %d", rr.Code)
	}
}

func TestBulkStateReplace(t *testing.T) {
	ts := newTestServer()

	// Create stack first
	stackReq := domain.CreateStackRequest{Name: "test-stack"}
	rr := ts.request("POST", "/api/v1/stacks", stackReq, ts.bootstrapKey)
	var stack domain.Stack
	_ = json.Unmarshal(rr.Body.Bytes(), &stack)

	// Create initial group
	groupReq := domain.CreateGroupRequest{
		Name:    "group:old",
		Members: []string{"old@example.com"},
	}
	ts.request("POST", "/api/v1/stacks/"+stack.ID+"/groups", groupReq, ts.bootstrapKey)

	// Replace state
	state := domain.StackState{
		Groups: []domain.CreateGroupRequest{
			{Name: "group:new1", Members: []string{"user1@example.com"}},
			{Name: "group:new2", Members: []string{"user2@example.com"}},
		},
		Hosts: []domain.CreateHostRequest{
			{Name: "server1", Address: "10.0.0.1"},
		},
		ACLs: []domain.CreateACLRuleRequest{
			{Action: "accept", Sources: []string{"*"}, Destinations: []string{"*:443"}},
		},
	}
	rr = ts.request("PUT", "/api/v1/stacks/"+stack.ID+"/state", state, ts.bootstrapKey)
	if rr.Code != http.StatusOK {
		t.Fatalf("Expected status 200, got %d: %s", rr.Code, rr.Body.String())
	}

	// Verify old group is gone
	rr = ts.request("GET", "/api/v1/stacks/"+stack.ID+"/groups/name/group:old", nil, ts.bootstrapKey)
	if rr.Code != http.StatusNotFound {
		t.Errorf("Expected old group to be deleted, got status %d", rr.Code)
	}

	// Verify new groups exist
	rr = ts.request("GET", "/api/v1/stacks/"+stack.ID+"/groups", nil, ts.bootstrapKey)
	var groups []*domain.Group
	_ = json.Unmarshal(rr.Body.Bytes(), &groups)
	if len(groups) != 2 {
		t.Errorf("Expected 2 groups, got %d", len(groups))
	}

	// Verify hosts
	rr = ts.request("GET", "/api/v1/stacks/"+stack.ID+"/hosts", nil, ts.bootstrapKey)
	var hosts []*domain.Host
	_ = json.Unmarshal(rr.Body.Bytes(), &hosts)
	if len(hosts) != 1 {
		t.Errorf("Expected 1 host, got %d", len(hosts))
	}

	// Verify ACLs
	rr = ts.request("GET", "/api/v1/stacks/"+stack.ID+"/acls", nil, ts.bootstrapKey)
	var rules []*domain.ACLRule
	_ = json.Unmarshal(rr.Body.Bytes(), &rules)
	if len(rules) != 1 {
		t.Errorf("Expected 1 ACL rule, got %d", len(rules))
	}
}

func TestPolicyPreview(t *testing.T) {
	ts := newTestServer()

	// Create stack with resources
	stackReq := domain.CreateStackRequest{Name: "test-stack", Priority: 10}
	rr := ts.request("POST", "/api/v1/stacks", stackReq, ts.bootstrapKey)
	var stack domain.Stack
	_ = json.Unmarshal(rr.Body.Bytes(), &stack)

	// Add some resources
	groupReq := domain.CreateGroupRequest{
		Name:    "group:developers",
		Members: []string{"dev@example.com"},
	}
	ts.request("POST", "/api/v1/stacks/"+stack.ID+"/groups", groupReq, ts.bootstrapKey)

	aclReq := domain.CreateACLRuleRequest{
		Action:       "accept",
		Sources:      []string{"group:developers"},
		Destinations: []string{"*:*"},
	}
	ts.request("POST", "/api/v1/stacks/"+stack.ID+"/acls", aclReq, ts.bootstrapKey)

	// Get policy preview
	rr = ts.request("GET", "/api/v1/policy/preview", nil, ts.bootstrapKey)
	if rr.Code != http.StatusOK {
		t.Fatalf("Expected status 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var policy domain.TailscalePolicy
	_ = json.Unmarshal(rr.Body.Bytes(), &policy)

	if len(policy.Groups) != 1 {
		t.Errorf("Expected 1 group in policy, got %d", len(policy.Groups))
	}
	if len(policy.ACLs) != 1 {
		t.Errorf("Expected 1 ACL in policy, got %d", len(policy.ACLs))
	}
}

func TestSSHRuleCRUD(t *testing.T) {
	ts := newTestServer()

	// Create stack first
	stackReq := domain.CreateStackRequest{Name: "test-stack"}
	rr := ts.request("POST", "/api/v1/stacks", stackReq, ts.bootstrapKey)
	var stack domain.Stack
	_ = json.Unmarshal(rr.Body.Bytes(), &stack)

	// Create SSH rule
	sshReq := domain.CreateSSHRuleRequest{
		Action:       "accept",
		Sources:      []string{"group:admins"},
		Destinations: []string{"tag:server"},
		Users:        []string{"root", "admin"},
	}
	rr = ts.request("POST", "/api/v1/stacks/"+stack.ID+"/ssh", sshReq, ts.bootstrapKey)
	if rr.Code != http.StatusCreated {
		t.Fatalf("Expected status 201, got %d: %s", rr.Code, rr.Body.String())
	}

	var rule domain.SSHRule
	_ = json.Unmarshal(rr.Body.Bytes(), &rule)
	if rule.Action != "accept" {
		t.Errorf("Expected action 'accept', got '%s'", rule.Action)
	}
	if len(rule.Users) != 2 {
		t.Errorf("Expected 2 users, got %d", len(rule.Users))
	}

	// Delete SSH rule
	rr = ts.request("DELETE", "/api/v1/stacks/"+stack.ID+"/ssh/"+rule.ID, nil, ts.bootstrapKey)
	if rr.Code != http.StatusNoContent {
		t.Errorf("Expected status 204, got %d", rr.Code)
	}
}

func TestTagOwnerCRUD(t *testing.T) {
	ts := newTestServer()

	// Create stack first
	stackReq := domain.CreateStackRequest{Name: "test-stack"}
	rr := ts.request("POST", "/api/v1/stacks", stackReq, ts.bootstrapKey)
	var stack domain.Stack
	_ = json.Unmarshal(rr.Body.Bytes(), &stack)

	// Create tag owner
	tagReq := domain.CreateTagOwnerRequest{
		Tag:    "tag:server",
		Owners: []string{"group:admins", "autogroup:admin"},
	}
	rr = ts.request("POST", "/api/v1/stacks/"+stack.ID+"/tags", tagReq, ts.bootstrapKey)
	if rr.Code != http.StatusCreated {
		t.Fatalf("Expected status 201, got %d: %s", rr.Code, rr.Body.String())
	}

	var tagOwner domain.TagOwner
	_ = json.Unmarshal(rr.Body.Bytes(), &tagOwner)
	if tagOwner.Tag != "tag:server" {
		t.Errorf("Expected tag 'tag:server', got '%s'", tagOwner.Tag)
	}
	if len(tagOwner.Owners) != 2 {
		t.Errorf("Expected 2 owners, got %d", len(tagOwner.Owners))
	}

	// Get tag owner
	rr = ts.request("GET", "/api/v1/stacks/"+stack.ID+"/tags/name/tag:server", nil, ts.bootstrapKey)
	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
	}

	// Delete tag owner
	rr = ts.request("DELETE", "/api/v1/stacks/"+stack.ID+"/tags/name/tag:server", nil, ts.bootstrapKey)
	if rr.Code != http.StatusNoContent {
		t.Errorf("Expected status 204, got %d", rr.Code)
	}
}

func TestAutoApproverCRUD(t *testing.T) {
	ts := newTestServer()

	// Create stack first
	stackReq := domain.CreateStackRequest{Name: "test-stack"}
	rr := ts.request("POST", "/api/v1/stacks", stackReq, ts.bootstrapKey)
	var stack domain.Stack
	_ = json.Unmarshal(rr.Body.Bytes(), &stack)

	// Create auto approver
	aaReq := domain.CreateAutoApproverRequest{
		Type:      "routes",
		Match:     "10.0.0.0/8",
		Approvers: []string{"group:network-admins"},
	}
	rr = ts.request("POST", "/api/v1/stacks/"+stack.ID+"/autoapprovers", aaReq, ts.bootstrapKey)
	if rr.Code != http.StatusCreated {
		t.Fatalf("Expected status 201, got %d: %s", rr.Code, rr.Body.String())
	}

	var aa domain.AutoApprover
	_ = json.Unmarshal(rr.Body.Bytes(), &aa)
	if aa.Type != "routes" {
		t.Errorf("Expected type 'routes', got '%s'", aa.Type)
	}
	if aa.Match != "10.0.0.0/8" {
		t.Errorf("Expected match '10.0.0.0/8', got '%s'", aa.Match)
	}

	// Delete auto approver
	rr = ts.request("DELETE", "/api/v1/stacks/"+stack.ID+"/autoapprovers/"+aa.ID, nil, ts.bootstrapKey)
	if rr.Code != http.StatusNoContent {
		t.Errorf("Expected status 204, got %d", rr.Code)
	}
}

func TestInvalidRequests(t *testing.T) {
	ts := newTestServer()

	// Create stack with missing name
	rr := ts.request("POST", "/api/v1/stacks", map[string]string{}, ts.bootstrapKey)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", rr.Code)
	}

	// Get non-existent stack
	rr = ts.request("GET", "/api/v1/stacks/nonexistent", nil, ts.bootstrapKey)
	if rr.Code != http.StatusNotFound {
		t.Errorf("Expected status 404, got %d", rr.Code)
	}

	// Create group without stack
	rr = ts.request("POST", "/api/v1/stacks/nonexistent/groups", map[string]any{
		"name":    "group:test",
		"members": []string{},
	}, ts.bootstrapKey)
	if rr.Code != http.StatusNotFound {
		t.Errorf("Expected status 404, got %d", rr.Code)
	}

	// Create ACL without src/dst
	stackReq := domain.CreateStackRequest{Name: "test-stack"}
	rr = ts.request("POST", "/api/v1/stacks", stackReq, ts.bootstrapKey)
	var stack domain.Stack
	_ = json.Unmarshal(rr.Body.Bytes(), &stack)

	rr = ts.request("POST", "/api/v1/stacks/"+stack.ID+"/acls", map[string]any{
		"action": "accept",
	}, ts.bootstrapKey)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400 for missing src/dst, got %d", rr.Code)
	}
}
