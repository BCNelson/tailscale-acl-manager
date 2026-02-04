package handler

import (
	"context"
	"net/http"

	"github.com/bcnelson/tailscale-acl-manager/internal/domain"
	"github.com/bcnelson/tailscale-acl-manager/internal/storage"
)

// ImportHandler handles import lookup endpoints for Pulumi provider support.
type ImportHandler struct {
	store storage.Storage
}

// NewImportHandler creates a new ImportHandler.
func NewImportHandler(store storage.Storage) *ImportHandler {
	return &ImportHandler{store: store}
}

// ImportResponse is the response format for import lookups.
type ImportResponse struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	StackID  string `json:"stack_id"`
	Name     string `json:"name"`
	Resource any    `json:"resource"`
}

// Lookup handles GET /api/v1/import?type=<type>&stack=<stack_id>&name=<name>
// This allows Pulumi import workflows to look up resources by composite key to get the UUID.
func (h *ImportHandler) Lookup(w http.ResponseWriter, r *http.Request) {
	resourceType := r.URL.Query().Get("type")
	stackID := r.URL.Query().Get("stack")
	name := r.URL.Query().Get("name")

	if resourceType == "" || stackID == "" || name == "" {
		respondStandardError(w, http.StatusBadRequest, domain.ErrCodeInvalidInput,
			"type, stack, and name query parameters are required", "", nil)
		return
	}

	ctx := r.Context()

	// Verify stack exists
	if _, err := h.store.GetStack(ctx, stackID); err != nil {
		handleError(w, err)
		return
	}

	var response *ImportResponse
	var err error

	switch resourceType {
	case "group":
		response, err = h.lookupGroup(ctx, stackID, name)
	case "tagowner", "tag":
		response, err = h.lookupTagOwner(ctx, stackID, name)
	case "host":
		response, err = h.lookupHost(ctx, stackID, name)
	case "posture":
		response, err = h.lookupPosture(ctx, stackID, name)
	case "ipset":
		response, err = h.lookupIPSet(ctx, stackID, name)
	case "acl":
		response, err = h.lookupACL(ctx, name) // ACL uses ID, not stack+name
	case "ssh":
		response, err = h.lookupSSH(ctx, name) // SSH uses ID
	case "grant":
		response, err = h.lookupGrant(ctx, name) // Grant uses ID
	case "autoapprover":
		response, err = h.lookupAutoApprover(ctx, name) // AutoApprover uses ID
	case "nodeattr":
		response, err = h.lookupNodeAttr(ctx, name) // NodeAttr uses ID
	case "acltest", "test":
		response, err = h.lookupACLTest(ctx, name) // ACLTest uses ID
	case "stack":
		response, err = h.lookupStack(ctx, name) // Stack by name
	default:
		respondStandardError(w, http.StatusBadRequest, domain.ErrCodeInvalidInput,
			"unknown resource type: "+resourceType, "type", nil)
		return
	}

	if err != nil {
		handleError(w, err)
		return
	}

	respondJSON(w, http.StatusOK, response)
}

func (h *ImportHandler) lookupGroup(ctx context.Context, stackID, name string) (*ImportResponse, error) {
	group, err := h.store.GetGroup(ctx, stackID, name)
	if err != nil {
		return nil, err
	}
	return &ImportResponse{
		ID:       group.ID,
		Type:     "group",
		StackID:  group.StackID,
		Name:     group.Name,
		Resource: group,
	}, nil
}

func (h *ImportHandler) lookupTagOwner(ctx context.Context, stackID, tag string) (*ImportResponse, error) {
	tagOwner, err := h.store.GetTagOwner(ctx, stackID, tag)
	if err != nil {
		return nil, err
	}
	return &ImportResponse{
		ID:       tagOwner.ID,
		Type:     "tagowner",
		StackID:  tagOwner.StackID,
		Name:     tagOwner.Tag,
		Resource: tagOwner,
	}, nil
}

func (h *ImportHandler) lookupHost(ctx context.Context, stackID, name string) (*ImportResponse, error) {
	host, err := h.store.GetHost(ctx, stackID, name)
	if err != nil {
		return nil, err
	}
	return &ImportResponse{
		ID:       host.ID,
		Type:     "host",
		StackID:  host.StackID,
		Name:     host.Name,
		Resource: host,
	}, nil
}

func (h *ImportHandler) lookupPosture(ctx context.Context, stackID, name string) (*ImportResponse, error) {
	posture, err := h.store.GetPosture(ctx, stackID, name)
	if err != nil {
		return nil, err
	}
	return &ImportResponse{
		ID:       posture.ID,
		Type:     "posture",
		StackID:  posture.StackID,
		Name:     posture.Name,
		Resource: posture,
	}, nil
}

func (h *ImportHandler) lookupIPSet(ctx context.Context, stackID, name string) (*ImportResponse, error) {
	ipset, err := h.store.GetIPSet(ctx, stackID, name)
	if err != nil {
		return nil, err
	}
	return &ImportResponse{
		ID:       ipset.ID,
		Type:     "ipset",
		StackID:  ipset.StackID,
		Name:     ipset.Name,
		Resource: ipset,
	}, nil
}

func (h *ImportHandler) lookupACL(ctx context.Context, id string) (*ImportResponse, error) {
	acl, err := h.store.GetACLRule(ctx, id)
	if err != nil {
		return nil, err
	}
	return &ImportResponse{
		ID:       acl.ID,
		Type:     "acl",
		StackID:  acl.StackID,
		Name:     acl.ID, // ACLs don't have names, use ID
		Resource: acl,
	}, nil
}

func (h *ImportHandler) lookupSSH(ctx context.Context, id string) (*ImportResponse, error) {
	ssh, err := h.store.GetSSHRule(ctx, id)
	if err != nil {
		return nil, err
	}
	return &ImportResponse{
		ID:       ssh.ID,
		Type:     "ssh",
		StackID:  ssh.StackID,
		Name:     ssh.ID,
		Resource: ssh,
	}, nil
}

func (h *ImportHandler) lookupGrant(ctx context.Context, id string) (*ImportResponse, error) {
	grant, err := h.store.GetGrant(ctx, id)
	if err != nil {
		return nil, err
	}
	return &ImportResponse{
		ID:       grant.ID,
		Type:     "grant",
		StackID:  grant.StackID,
		Name:     grant.ID,
		Resource: grant,
	}, nil
}

func (h *ImportHandler) lookupAutoApprover(ctx context.Context, id string) (*ImportResponse, error) {
	aa, err := h.store.GetAutoApprover(ctx, id)
	if err != nil {
		return nil, err
	}
	return &ImportResponse{
		ID:       aa.ID,
		Type:     "autoapprover",
		StackID:  aa.StackID,
		Name:     aa.ID,
		Resource: aa,
	}, nil
}

func (h *ImportHandler) lookupNodeAttr(ctx context.Context, id string) (*ImportResponse, error) {
	attr, err := h.store.GetNodeAttr(ctx, id)
	if err != nil {
		return nil, err
	}
	return &ImportResponse{
		ID:       attr.ID,
		Type:     "nodeattr",
		StackID:  attr.StackID,
		Name:     attr.ID,
		Resource: attr,
	}, nil
}

func (h *ImportHandler) lookupACLTest(ctx context.Context, id string) (*ImportResponse, error) {
	test, err := h.store.GetACLTest(ctx, id)
	if err != nil {
		return nil, err
	}
	return &ImportResponse{
		ID:       test.ID,
		Type:     "acltest",
		StackID:  test.StackID,
		Name:     test.ID,
		Resource: test,
	}, nil
}

func (h *ImportHandler) lookupStack(ctx context.Context, name string) (*ImportResponse, error) {
	stack, err := h.store.GetStackByName(ctx, name)
	if err != nil {
		return nil, err
	}
	return &ImportResponse{
		ID:       stack.ID,
		Type:     "stack",
		StackID:  stack.ID, // Stack's own ID
		Name:     stack.Name,
		Resource: stack,
	}, nil
}
