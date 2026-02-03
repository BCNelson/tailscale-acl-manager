package web

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/bcnelson/tailscale-acl-manager/internal/domain"
	"github.com/bcnelson/tailscale-acl-manager/internal/validation"
	"github.com/go-chi/chi/v5"
)

// ResourceMeta holds metadata about a resource type.
type ResourceMeta struct {
	Name     string
	Singular string
	Plural   string
	IDField  string // "name", "tag", or "id"
	Fields   []FieldMeta
	HasOrder bool
}

// FieldMeta describes a form field for a resource.
type FieldMeta struct {
	Name              string
	Label             string
	Type              string // "text", "textarea", "number", "select"
	Required          bool
	Help              string
	Placeholder       string
	Options           []SelectOption // For select fields
	ValidationPattern string         // HTML5 pattern attribute for client-side validation
	ValidationMessage string         // Error message shown when validation fails
}

// SelectOption is an option for select fields.
type SelectOption struct {
	Value string
	Label string
}

// resourceTypes maps resource names to their metadata.
var resourceTypes = map[string]ResourceMeta{
	"groups": {
		Name:     "groups",
		Singular: "Group",
		Plural:   "Groups",
		IDField:  "name",
		Fields: []FieldMeta{
			{Name: "name", Label: "Name", Type: "text", Required: true, Help: "e.g., group:developers", Placeholder: "group:name",
				ValidationPattern: `^group:[a-zA-Z][a-zA-Z0-9\-]*$`,
				ValidationMessage: "Must be 'group:' followed by a letter, then letters/numbers/hyphens only (no underscores)"},
			{Name: "members", Label: "Members", Type: "textarea", Required: true, Help: "One member per line (users or groups)", Placeholder: "user@example.com\ngroup:other"},
		},
	},
	"tags": {
		Name:     "tags",
		Singular: "Tag Owner",
		Plural:   "Tag Owners",
		IDField:  "tag",
		Fields: []FieldMeta{
			{Name: "tag", Label: "Tag", Type: "text", Required: true, Help: "e.g., tag:server", Placeholder: "tag:name",
				ValidationPattern: `^tag:[a-zA-Z][a-zA-Z0-9\-]*$`,
				ValidationMessage: "Must be 'tag:' followed by a letter, then letters/numbers/hyphens only (no underscores)"},
			{Name: "owners", Label: "Owners", Type: "textarea", Required: true, Help: "One owner per line", Placeholder: "group:admins\nuser@example.com"},
		},
	},
	"hosts": {
		Name:     "hosts",
		Singular: "Host",
		Plural:   "Hosts",
		IDField:  "name",
		Fields: []FieldMeta{
			{Name: "name", Label: "Name", Type: "text", Required: true, Help: "Alias name for the IP", Placeholder: "myserver",
				ValidationPattern: `^[a-zA-Z][a-zA-Z0-9\-]*$`,
				ValidationMessage: "Must start with a letter, then letters/numbers/hyphens only"},
			{Name: "address", Label: "Address", Type: "text", Required: true, Help: "IP address or CIDR", Placeholder: "100.64.0.1"},
		},
	},
	"acls": {
		Name:     "acls",
		Singular: "ACL Rule",
		Plural:   "ACL Rules",
		IDField:  "id",
		HasOrder: true,
		Fields: []FieldMeta{
			{Name: "action", Label: "Action", Type: "select", Required: true, Options: []SelectOption{{Value: "accept", Label: "Accept"}, {Value: "deny", Label: "Deny"}}},
			{Name: "protocol", Label: "Protocol", Type: "text", Help: "Optional: tcp, udp, icmp, or empty for all", Placeholder: "tcp"},
			{Name: "src", Label: "Sources", Type: "textarea", Required: true, Help: "One source per line", Placeholder: "*\ngroup:developers"},
			{Name: "dst", Label: "Destinations", Type: "textarea", Required: true, Help: "One destination per line (with optional ports)", Placeholder: "tag:server:22\n100.64.0.0/24:*"},
		},
	},
	"ssh": {
		Name:     "ssh",
		Singular: "SSH Rule",
		Plural:   "SSH Rules",
		IDField:  "id",
		HasOrder: true,
		Fields: []FieldMeta{
			{Name: "action", Label: "Action", Type: "select", Required: true, Options: []SelectOption{{Value: "accept", Label: "Accept"}, {Value: "check", Label: "Check"}}},
			{Name: "src", Label: "Sources", Type: "textarea", Required: true, Help: "One source per line", Placeholder: "group:developers"},
			{Name: "dst", Label: "Destinations", Type: "textarea", Required: true, Help: "One destination per line", Placeholder: "tag:server"},
			{Name: "users", Label: "Users", Type: "textarea", Required: true, Help: "SSH users allowed", Placeholder: "root\nautogroup:nonroot"},
			{Name: "checkPeriod", Label: "Check Period", Type: "text", Help: "For action=check only", Placeholder: "12h"},
		},
	},
	"grants": {
		Name:     "grants",
		Singular: "Grant",
		Plural:   "Grants",
		IDField:  "id",
		HasOrder: true,
		Fields: []FieldMeta{
			{Name: "src", Label: "Sources", Type: "textarea", Required: true, Help: "One source per line", Placeholder: "group:developers"},
			{Name: "dst", Label: "Destinations", Type: "textarea", Required: true, Help: "One destination per line", Placeholder: "tag:server"},
			{Name: "ip", Label: "IP Permissions", Type: "textarea", Help: "Optional: IP addresses", Placeholder: "*"},
		},
	},
	"autoapprovers": {
		Name:     "autoapprovers",
		Singular: "Auto Approver",
		Plural:   "Auto Approvers",
		IDField:  "id",
		Fields: []FieldMeta{
			{Name: "type", Label: "Type", Type: "select", Required: true, Options: []SelectOption{{Value: "routes", Label: "Routes"}, {Value: "exitNode", Label: "Exit Node"}}},
			{Name: "match", Label: "Match", Type: "text", Required: true, Help: "Route CIDR or * for exit nodes", Placeholder: "10.0.0.0/8"},
			{Name: "approvers", Label: "Approvers", Type: "textarea", Required: true, Help: "One approver per line", Placeholder: "group:admins\ntag:server"},
		},
	},
	"nodeattrs": {
		Name:     "nodeattrs",
		Singular: "Node Attribute",
		Plural:   "Node Attributes",
		IDField:  "id",
		HasOrder: true,
		Fields: []FieldMeta{
			{Name: "target", Label: "Target", Type: "textarea", Required: true, Help: "One target per line", Placeholder: "tag:server\ngroup:developers"},
			{Name: "attr", Label: "Attributes", Type: "textarea", Help: "One attribute per line", Placeholder: "funnel"},
		},
	},
	"postures": {
		Name:     "postures",
		Singular: "Posture",
		Plural:   "Postures",
		IDField:  "name",
		Fields: []FieldMeta{
			{Name: "name", Label: "Name", Type: "text", Required: true, Help: "Posture name", Placeholder: "latestMac"},
			{Name: "rules", Label: "Rules", Type: "textarea", Required: true, Help: "Posture check expressions, one per line", Placeholder: "node:os == 'macos'\nnode:osVersion >= '14'"},
		},
	},
	"ipsets": {
		Name:     "ipsets",
		Singular: "IP Set",
		Plural:   "IP Sets",
		IDField:  "name",
		Fields: []FieldMeta{
			{Name: "name", Label: "Name", Type: "text", Required: true, Help: "IP Set name (must include ipset: prefix)", Placeholder: "ipset:office-ips",
				ValidationPattern: `^ipset:[a-zA-Z][a-zA-Z0-9\-]*$`,
				ValidationMessage: "Must be 'ipset:' followed by a letter, then letters/numbers/hyphens only"},
			{Name: "addresses", Label: "Addresses", Type: "textarea", Required: true, Help: "IP addresses or CIDRs, one per line", Placeholder: "192.168.1.0/24\n10.0.0.1"},
		},
	},
	"tests": {
		Name:     "tests",
		Singular: "ACL Test",
		Plural:   "ACL Tests",
		IDField:  "id",
		HasOrder: true,
		Fields: []FieldMeta{
			{Name: "src", Label: "Source", Type: "text", Required: true, Help: "Source for the test", Placeholder: "user@example.com"},
			{Name: "accept", Label: "Accept", Type: "textarea", Help: "Destinations that should be allowed", Placeholder: "tag:server:22"},
			{Name: "deny", Label: "Deny", Type: "textarea", Help: "Destinations that should be denied", Placeholder: "tag:private:*"},
		},
	},
}

// ResourceListData holds data for resource list.
type ResourceListData struct {
	StackID  string
	Resource ResourceMeta
	Items    []map[string]any
}

// ResourceFormData holds data for resource form.
type ResourceFormData struct {
	StackID  string
	Resource ResourceMeta
	Item     map[string]any
	IsEdit   bool
}

// handleResourceList handles listing resources of a type.
func (s *Server) handleResourceList(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	stackID := chi.URLParam(r, "id")
	resourceType := chi.URLParam(r, "resource")

	meta, ok := resourceTypes[resourceType]
	if !ok {
		s.renderError(w, "Unknown resource type", http.StatusBadRequest)
		return
	}

	items, err := s.listResources(ctx, stackID, resourceType)
	if err != nil {
		s.renderError(w, "Failed to load resources", http.StatusInternalServerError)
		return
	}

	data := ResourceListData{
		StackID:  stackID,
		Resource: meta,
		Items:    items,
	}

	s.renderFragment(w, "resource_list", data)
}

// handleResourceForm renders the new resource form.
func (s *Server) handleResourceForm(w http.ResponseWriter, r *http.Request) {
	stackID := chi.URLParam(r, "id")
	resourceType := chi.URLParam(r, "resource")

	meta, ok := resourceTypes[resourceType]
	if !ok {
		s.renderError(w, "Unknown resource type", http.StatusBadRequest)
		return
	}

	data := ResourceFormData{
		StackID:  stackID,
		Resource: meta,
		Item:     make(map[string]any),
		IsEdit:   false,
	}

	s.renderFragment(w, "resource_form", data)
}

// handleResourceCreate creates a new resource.
func (s *Server) handleResourceCreate(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.renderError(w, "Invalid form data", http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	stackID := chi.URLParam(r, "id")
	resourceType := chi.URLParam(r, "resource")

	meta, ok := resourceTypes[resourceType]
	if !ok {
		s.renderError(w, "Unknown resource type", http.StatusBadRequest)
		return
	}

	// Verify stack exists
	_, err := s.store.GetStack(ctx, stackID)
	if err != nil {
		if err == domain.ErrNotFound {
			s.renderError(w, "Stack not found", http.StatusNotFound)
			return
		}
		s.renderError(w, "Failed to verify stack", http.StatusInternalServerError)
		return
	}

	err = s.createResource(ctx, stackID, resourceType, r, meta)
	if err != nil {
		if err == domain.ErrAlreadyExists {
			s.renderError(w, "Resource already exists", http.StatusConflict)
			return
		}
		s.renderError(w, "Failed to create resource: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Trigger sync
	s.syncService.TriggerSync()

	w.Header().Set("HX-Redirect", "/stacks/"+stackID+"?tab="+resourceType)
	w.WriteHeader(http.StatusOK)
}

// handleResourceEditForm renders the edit form for a resource.
func (s *Server) handleResourceEditForm(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	stackID := chi.URLParam(r, "id")
	resourceType := chi.URLParam(r, "resource")
	name := chi.URLParam(r, "name")

	meta, ok := resourceTypes[resourceType]
	if !ok {
		s.renderError(w, "Unknown resource type", http.StatusBadRequest)
		return
	}

	item, err := s.getResource(ctx, stackID, resourceType, name)
	if err != nil {
		if err == domain.ErrNotFound {
			s.renderError(w, "Resource not found", http.StatusNotFound)
			return
		}
		s.renderError(w, "Failed to load resource", http.StatusInternalServerError)
		return
	}

	data := ResourceFormData{
		StackID:  stackID,
		Resource: meta,
		Item:     item,
		IsEdit:   true,
	}

	s.renderFragment(w, "resource_form", data)
}

// handleResourceUpdate updates an existing resource.
func (s *Server) handleResourceUpdate(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.renderError(w, "Invalid form data", http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	stackID := chi.URLParam(r, "id")
	resourceType := chi.URLParam(r, "resource")
	name := chi.URLParam(r, "name")

	meta, ok := resourceTypes[resourceType]
	if !ok {
		s.renderError(w, "Unknown resource type", http.StatusBadRequest)
		return
	}

	err := s.updateResource(ctx, stackID, resourceType, name, r, meta)
	if err != nil {
		if err == domain.ErrNotFound {
			s.renderError(w, "Resource not found", http.StatusNotFound)
			return
		}
		s.renderError(w, "Failed to update resource: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Trigger sync
	s.syncService.TriggerSync()

	w.Header().Set("HX-Redirect", "/stacks/"+stackID+"?tab="+resourceType)
	w.WriteHeader(http.StatusOK)
}

// handleResourceDelete deletes a resource.
func (s *Server) handleResourceDelete(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	stackID := chi.URLParam(r, "id")
	resourceType := chi.URLParam(r, "resource")
	name := chi.URLParam(r, "name")

	err := s.deleteResource(ctx, stackID, resourceType, name)
	if err != nil {
		if err == domain.ErrNotFound {
			s.renderError(w, "Resource not found", http.StatusNotFound)
			return
		}
		s.renderError(w, "Failed to delete resource", http.StatusInternalServerError)
		return
	}

	// Trigger sync
	s.syncService.TriggerSync()

	w.Header().Set("HX-Redirect", "/stacks/"+stackID+"?tab="+resourceType)
	w.WriteHeader(http.StatusOK)
}

// listResources lists resources of a given type.
func (s *Server) listResources(ctx context.Context, stackID, resourceType string) ([]map[string]any, error) {
	var items []map[string]any

	switch resourceType {
	case "groups":
		resources, err := s.store.ListGroups(ctx, stackID)
		if err != nil {
			return nil, err
		}
		for _, r := range resources {
			items = append(items, map[string]any{
				"id":      r.ID,
				"name":    r.Name,
				"members": strings.Join(r.Members, ", "),
			})
		}
	case "tags":
		resources, err := s.store.ListTagOwners(ctx, stackID)
		if err != nil {
			return nil, err
		}
		for _, r := range resources {
			items = append(items, map[string]any{
				"id":     r.ID,
				"tag":    r.Tag,
				"owners": strings.Join(r.Owners, ", "),
			})
		}
	case "hosts":
		resources, err := s.store.ListHosts(ctx, stackID)
		if err != nil {
			return nil, err
		}
		for _, r := range resources {
			items = append(items, map[string]any{
				"id":      r.ID,
				"name":    r.Name,
				"address": r.Address,
			})
		}
	case "acls":
		resources, err := s.store.ListACLRules(ctx, stackID)
		if err != nil {
			return nil, err
		}
		for _, r := range resources {
			items = append(items, map[string]any{
				"id":       r.ID,
				"order":    r.Order,
				"action":   r.Action,
				"protocol": r.Protocol,
				"src":      strings.Join(r.Sources, ", "),
				"dst":      strings.Join(r.Destinations, ", "),
			})
		}
	case "ssh":
		resources, err := s.store.ListSSHRules(ctx, stackID)
		if err != nil {
			return nil, err
		}
		for _, r := range resources {
			items = append(items, map[string]any{
				"id":          r.ID,
				"order":       r.Order,
				"action":      r.Action,
				"src":         strings.Join(r.Sources, ", "),
				"dst":         strings.Join(r.Destinations, ", "),
				"users":       strings.Join(r.Users, ", "),
				"checkPeriod": r.CheckPeriod,
			})
		}
	case "grants":
		resources, err := s.store.ListGrants(ctx, stackID)
		if err != nil {
			return nil, err
		}
		for _, r := range resources {
			items = append(items, map[string]any{
				"id":    r.ID,
				"order": r.Order,
				"src":   strings.Join(r.Sources, ", "),
				"dst":   strings.Join(r.Destinations, ", "),
				"ip":    strings.Join(r.IP, ", "),
			})
		}
	case "autoapprovers":
		resources, err := s.store.ListAutoApprovers(ctx, stackID)
		if err != nil {
			return nil, err
		}
		for _, r := range resources {
			items = append(items, map[string]any{
				"id":        r.ID,
				"type":      r.Type,
				"match":     r.Match,
				"approvers": strings.Join(r.Approvers, ", "),
			})
		}
	case "nodeattrs":
		resources, err := s.store.ListNodeAttrs(ctx, stackID)
		if err != nil {
			return nil, err
		}
		for _, r := range resources {
			items = append(items, map[string]any{
				"id":     r.ID,
				"order":  r.Order,
				"target": strings.Join(r.Target, ", "),
				"attr":   strings.Join(r.Attr, ", "),
			})
		}
	case "postures":
		resources, err := s.store.ListPostures(ctx, stackID)
		if err != nil {
			return nil, err
		}
		for _, r := range resources {
			items = append(items, map[string]any{
				"id":    r.ID,
				"name":  r.Name,
				"rules": strings.Join(r.Rules, ", "),
			})
		}
	case "ipsets":
		resources, err := s.store.ListIPSets(ctx, stackID)
		if err != nil {
			return nil, err
		}
		for _, r := range resources {
			items = append(items, map[string]any{
				"id":        r.ID,
				"name":      r.Name,
				"addresses": strings.Join(r.Addresses, ", "),
			})
		}
	case "tests":
		resources, err := s.store.ListACLTests(ctx, stackID)
		if err != nil {
			return nil, err
		}
		for _, r := range resources {
			items = append(items, map[string]any{
				"id":     r.ID,
				"order":  r.Order,
				"src":    r.Source,
				"accept": strings.Join(r.Accept, ", "),
				"deny":   strings.Join(r.Deny, ", "),
			})
		}
	}

	return items, nil
}

// getResource gets a single resource.
func (s *Server) getResource(ctx context.Context, stackID, resourceType, name string) (map[string]any, error) {
	switch resourceType {
	case "groups":
		r, err := s.store.GetGroup(ctx, stackID, name)
		if err != nil {
			return nil, err
		}
		return map[string]any{
			"id":      r.ID,
			"name":    r.Name,
			"members": r.Members,
		}, nil
	case "tags":
		r, err := s.store.GetTagOwner(ctx, stackID, name)
		if err != nil {
			return nil, err
		}
		return map[string]any{
			"id":     r.ID,
			"tag":    r.Tag,
			"owners": r.Owners,
		}, nil
	case "hosts":
		r, err := s.store.GetHost(ctx, stackID, name)
		if err != nil {
			return nil, err
		}
		return map[string]any{
			"id":      r.ID,
			"name":    r.Name,
			"address": r.Address,
		}, nil
	case "acls":
		r, err := s.store.GetACLRule(ctx, name)
		if err != nil {
			return nil, err
		}
		return map[string]any{
			"id":       r.ID,
			"order":    r.Order,
			"action":   r.Action,
			"protocol": r.Protocol,
			"src":      r.Sources,
			"dst":      r.Destinations,
		}, nil
	case "ssh":
		r, err := s.store.GetSSHRule(ctx, name)
		if err != nil {
			return nil, err
		}
		return map[string]any{
			"id":          r.ID,
			"order":       r.Order,
			"action":      r.Action,
			"src":         r.Sources,
			"dst":         r.Destinations,
			"users":       r.Users,
			"checkPeriod": r.CheckPeriod,
		}, nil
	case "grants":
		r, err := s.store.GetGrant(ctx, name)
		if err != nil {
			return nil, err
		}
		return map[string]any{
			"id":    r.ID,
			"order": r.Order,
			"src":   r.Sources,
			"dst":   r.Destinations,
			"ip":    r.IP,
		}, nil
	case "autoapprovers":
		r, err := s.store.GetAutoApprover(ctx, name)
		if err != nil {
			return nil, err
		}
		return map[string]any{
			"id":        r.ID,
			"type":      r.Type,
			"match":     r.Match,
			"approvers": r.Approvers,
		}, nil
	case "nodeattrs":
		r, err := s.store.GetNodeAttr(ctx, name)
		if err != nil {
			return nil, err
		}
		return map[string]any{
			"id":     r.ID,
			"order":  r.Order,
			"target": r.Target,
			"attr":   r.Attr,
		}, nil
	case "postures":
		r, err := s.store.GetPosture(ctx, stackID, name)
		if err != nil {
			return nil, err
		}
		return map[string]any{
			"id":    r.ID,
			"name":  r.Name,
			"rules": r.Rules,
		}, nil
	case "ipsets":
		r, err := s.store.GetIPSet(ctx, stackID, name)
		if err != nil {
			return nil, err
		}
		return map[string]any{
			"id":        r.ID,
			"name":      r.Name,
			"addresses": r.Addresses,
		}, nil
	case "tests":
		r, err := s.store.GetACLTest(ctx, name)
		if err != nil {
			return nil, err
		}
		return map[string]any{
			"id":     r.ID,
			"order":  r.Order,
			"src":    r.Source,
			"accept": r.Accept,
			"deny":   r.Deny,
		}, nil
	}
	return nil, domain.ErrNotFound
}

// validateResource validates resource data before create or update.
func validateResource(resourceType string, r *http.Request) error {
	switch resourceType {
	case "groups":
		name := r.FormValue("name")
		if err := validation.ValidateGroupName(name); err != nil {
			return fmt.Errorf("invalid group name: %w", err)
		}
		members := parseLines(r.FormValue("members"))
		for i, member := range members {
			if err := validation.ValidateGroupMember(member); err != nil {
				return fmt.Errorf("invalid member[%d] '%s': %w", i, member, err)
			}
		}
	case "tags":
		tag := r.FormValue("tag")
		if err := validation.ValidateTagName(tag); err != nil {
			return fmt.Errorf("invalid tag name: %w", err)
		}
		owners := parseLines(r.FormValue("owners"))
		for i, owner := range owners {
			if err := validation.ValidateTagOwner(owner); err != nil {
				return fmt.Errorf("invalid owner[%d] '%s': %w", i, owner, err)
			}
		}
	case "hosts":
		name := r.FormValue("name")
		if err := validation.ValidateHostName(name); err != nil {
			return fmt.Errorf("invalid host name: %w", err)
		}
		address := r.FormValue("address")
		if err := validation.ValidateHostAddress(address); err != nil {
			return fmt.Errorf("invalid address: %w", err)
		}
	case "acls":
		sources := parseLines(r.FormValue("src"))
		for i, src := range sources {
			if err := validation.ValidateACLSource(src); err != nil {
				return fmt.Errorf("invalid source[%d] '%s': %w", i, src, err)
			}
		}
		destinations := parseLines(r.FormValue("dst"))
		for i, dst := range destinations {
			if err := validation.ValidateACLDestination(dst); err != nil {
				return fmt.Errorf("invalid destination[%d] '%s': %w", i, dst, err)
			}
		}
	case "ssh":
		sources := parseLines(r.FormValue("src"))
		for i, src := range sources {
			if err := validation.ValidateACLSource(src); err != nil {
				return fmt.Errorf("invalid source[%d] '%s': %w", i, src, err)
			}
		}
		destinations := parseLines(r.FormValue("dst"))
		for i, dst := range destinations {
			if err := validation.ValidateACLSource(dst); err != nil { // SSH destinations use same format as sources
				return fmt.Errorf("invalid destination[%d] '%s': %w", i, dst, err)
			}
		}
		users := parseLines(r.FormValue("users"))
		for i, user := range users {
			if err := validation.ValidateSSHUser(user); err != nil {
				return fmt.Errorf("invalid user[%d] '%s': %w", i, user, err)
			}
		}
	case "grants":
		sources := parseLines(r.FormValue("src"))
		for i, src := range sources {
			if err := validation.ValidateACLSource(src); err != nil {
				return fmt.Errorf("invalid source[%d] '%s': %w", i, src, err)
			}
		}
		destinations := parseLines(r.FormValue("dst"))
		for i, dst := range destinations {
			if err := validation.ValidateACLSource(dst); err != nil { // Grant destinations use same format as sources
				return fmt.Errorf("invalid destination[%d] '%s': %w", i, dst, err)
			}
		}
	case "autoapprovers":
		approverType := r.FormValue("type")
		match := r.FormValue("match")
		if err := validation.ValidateAutoApproverMatch(approverType, match); err != nil {
			return fmt.Errorf("invalid match: %w", err)
		}
		approvers := parseLines(r.FormValue("approvers"))
		for i, approver := range approvers {
			if err := validation.ValidateAutoApprover(approver); err != nil {
				return fmt.Errorf("invalid approver[%d] '%s': %w", i, approver, err)
			}
		}
	case "nodeattrs":
		targets := parseLines(r.FormValue("target"))
		for i, target := range targets {
			if err := validation.ValidateNodeAttrTarget(target); err != nil {
				return fmt.Errorf("invalid target[%d] '%s': %w", i, target, err)
			}
		}
	case "ipsets":
		name := r.FormValue("name")
		if err := validation.ValidateIPSetName(name); err != nil {
			return fmt.Errorf("invalid IP set name: %w", err)
		}
		addresses := parseLines(r.FormValue("addresses"))
		for i, addr := range addresses {
			if err := validation.ValidateHostAddress(addr); err != nil {
				return fmt.Errorf("invalid address[%d] '%s': %w", i, addr, err)
			}
		}
	case "tests":
		src := r.FormValue("src")
		if src != "" {
			if err := validation.ValidateACLSource(src); err != nil {
				return fmt.Errorf("invalid test source: %w", err)
			}
		}
		// Accept and deny destinations can include port specifications
		accept := parseLines(r.FormValue("accept"))
		for i, dst := range accept {
			if err := validation.ValidateACLDestination(dst); err != nil {
				return fmt.Errorf("invalid accept[%d] '%s': %w", i, dst, err)
			}
		}
		deny := parseLines(r.FormValue("deny"))
		for i, dst := range deny {
			if err := validation.ValidateACLDestination(dst); err != nil {
				return fmt.Errorf("invalid deny[%d] '%s': %w", i, dst, err)
			}
		}
	}
	return nil
}

// createResource creates a new resource.
func (s *Server) createResource(ctx context.Context, stackID, resourceType string, r *http.Request, meta ResourceMeta) error {
	// Validate the resource data
	if err := validateResource(resourceType, r); err != nil {
		return err
	}

	now := time.Now()

	switch resourceType {
	case "groups":
		group := &domain.Group{
			ID:        generateID(),
			StackID:   stackID,
			Name:      r.FormValue("name"),
			Members:   parseLines(r.FormValue("members")),
			CreatedAt: now,
			UpdatedAt: now,
		}
		return s.store.CreateGroup(ctx, group)
	case "tags":
		tagOwner := &domain.TagOwner{
			ID:        generateID(),
			StackID:   stackID,
			Tag:       r.FormValue("tag"),
			Owners:    parseLines(r.FormValue("owners")),
			CreatedAt: now,
			UpdatedAt: now,
		}
		return s.store.CreateTagOwner(ctx, tagOwner)
	case "hosts":
		host := &domain.Host{
			ID:        generateID(),
			StackID:   stackID,
			Name:      r.FormValue("name"),
			Address:   r.FormValue("address"),
			CreatedAt: now,
			UpdatedAt: now,
		}
		return s.store.CreateHost(ctx, host)
	case "acls":
		rule := &domain.ACLRule{
			ID:           generateID(),
			StackID:      stackID,
			Order:        parseInt(r.FormValue("order"), 0),
			Action:       r.FormValue("action"),
			Protocol:     r.FormValue("protocol"),
			Sources:      parseLines(r.FormValue("src")),
			Destinations: parseLines(r.FormValue("dst")),
			CreatedAt:    now,
			UpdatedAt:    now,
		}
		return s.store.CreateACLRule(ctx, rule)
	case "ssh":
		rule := &domain.SSHRule{
			ID:           generateID(),
			StackID:      stackID,
			Order:        parseInt(r.FormValue("order"), 0),
			Action:       r.FormValue("action"),
			Sources:      parseLines(r.FormValue("src")),
			Destinations: parseLines(r.FormValue("dst")),
			Users:        parseLines(r.FormValue("users")),
			CheckPeriod:  r.FormValue("checkPeriod"),
			CreatedAt:    now,
			UpdatedAt:    now,
		}
		return s.store.CreateSSHRule(ctx, rule)
	case "grants":
		grant := &domain.Grant{
			ID:           generateID(),
			StackID:      stackID,
			Order:        parseInt(r.FormValue("order"), 0),
			Sources:      parseLines(r.FormValue("src")),
			Destinations: parseLines(r.FormValue("dst")),
			IP:           parseLines(r.FormValue("ip")),
			CreatedAt:    now,
			UpdatedAt:    now,
		}
		return s.store.CreateGrant(ctx, grant)
	case "autoapprovers":
		aa := &domain.AutoApprover{
			ID:        generateID(),
			StackID:   stackID,
			Type:      r.FormValue("type"),
			Match:     r.FormValue("match"),
			Approvers: parseLines(r.FormValue("approvers")),
			CreatedAt: now,
			UpdatedAt: now,
		}
		return s.store.CreateAutoApprover(ctx, aa)
	case "nodeattrs":
		attr := &domain.NodeAttr{
			ID:        generateID(),
			StackID:   stackID,
			Order:     parseInt(r.FormValue("order"), 0),
			Target:    parseLines(r.FormValue("target")),
			Attr:      parseLines(r.FormValue("attr")),
			CreatedAt: now,
			UpdatedAt: now,
		}
		return s.store.CreateNodeAttr(ctx, attr)
	case "postures":
		posture := &domain.Posture{
			ID:        generateID(),
			StackID:   stackID,
			Name:      r.FormValue("name"),
			Rules:     parseLines(r.FormValue("rules")),
			CreatedAt: now,
			UpdatedAt: now,
		}
		return s.store.CreatePosture(ctx, posture)
	case "ipsets":
		ipset := &domain.IPSet{
			ID:        generateID(),
			StackID:   stackID,
			Name:      r.FormValue("name"),
			Addresses: parseLines(r.FormValue("addresses")),
			CreatedAt: now,
			UpdatedAt: now,
		}
		return s.store.CreateIPSet(ctx, ipset)
	case "tests":
		test := &domain.ACLTest{
			ID:        generateID(),
			StackID:   stackID,
			Order:     parseInt(r.FormValue("order"), 0),
			Source:    r.FormValue("src"),
			Accept:    parseLines(r.FormValue("accept")),
			Deny:      parseLines(r.FormValue("deny")),
			CreatedAt: now,
			UpdatedAt: now,
		}
		return s.store.CreateACLTest(ctx, test)
	}
	return domain.ErrInvalidInput
}

// updateResource updates an existing resource.
func (s *Server) updateResource(ctx context.Context, stackID, resourceType, name string, r *http.Request, meta ResourceMeta) error {
	// Validate the resource data (for updates, validateResource works on the same form fields)
	if err := validateResource(resourceType, r); err != nil {
		return err
	}

	now := time.Now()

	switch resourceType {
	case "groups":
		group, err := s.store.GetGroup(ctx, stackID, name)
		if err != nil {
			return err
		}
		group.Members = parseLines(r.FormValue("members"))
		group.UpdatedAt = now
		return s.store.UpdateGroup(ctx, group)
	case "tags":
		tagOwner, err := s.store.GetTagOwner(ctx, stackID, name)
		if err != nil {
			return err
		}
		tagOwner.Owners = parseLines(r.FormValue("owners"))
		tagOwner.UpdatedAt = now
		return s.store.UpdateTagOwner(ctx, tagOwner)
	case "hosts":
		host, err := s.store.GetHost(ctx, stackID, name)
		if err != nil {
			return err
		}
		host.Address = r.FormValue("address")
		host.UpdatedAt = now
		return s.store.UpdateHost(ctx, host)
	case "acls":
		rule, err := s.store.GetACLRule(ctx, name)
		if err != nil {
			return err
		}
		rule.Order = parseInt(r.FormValue("order"), rule.Order)
		rule.Action = r.FormValue("action")
		rule.Protocol = r.FormValue("protocol")
		rule.Sources = parseLines(r.FormValue("src"))
		rule.Destinations = parseLines(r.FormValue("dst"))
		rule.UpdatedAt = now
		return s.store.UpdateACLRule(ctx, rule)
	case "ssh":
		rule, err := s.store.GetSSHRule(ctx, name)
		if err != nil {
			return err
		}
		rule.Order = parseInt(r.FormValue("order"), rule.Order)
		rule.Action = r.FormValue("action")
		rule.Sources = parseLines(r.FormValue("src"))
		rule.Destinations = parseLines(r.FormValue("dst"))
		rule.Users = parseLines(r.FormValue("users"))
		rule.CheckPeriod = r.FormValue("checkPeriod")
		rule.UpdatedAt = now
		return s.store.UpdateSSHRule(ctx, rule)
	case "grants":
		grant, err := s.store.GetGrant(ctx, name)
		if err != nil {
			return err
		}
		grant.Order = parseInt(r.FormValue("order"), grant.Order)
		grant.Sources = parseLines(r.FormValue("src"))
		grant.Destinations = parseLines(r.FormValue("dst"))
		grant.IP = parseLines(r.FormValue("ip"))
		grant.UpdatedAt = now
		return s.store.UpdateGrant(ctx, grant)
	case "autoapprovers":
		aa, err := s.store.GetAutoApprover(ctx, name)
		if err != nil {
			return err
		}
		aa.Type = r.FormValue("type")
		aa.Match = r.FormValue("match")
		aa.Approvers = parseLines(r.FormValue("approvers"))
		aa.UpdatedAt = now
		return s.store.UpdateAutoApprover(ctx, aa)
	case "nodeattrs":
		attr, err := s.store.GetNodeAttr(ctx, name)
		if err != nil {
			return err
		}
		attr.Order = parseInt(r.FormValue("order"), attr.Order)
		attr.Target = parseLines(r.FormValue("target"))
		attr.Attr = parseLines(r.FormValue("attr"))
		attr.UpdatedAt = now
		return s.store.UpdateNodeAttr(ctx, attr)
	case "postures":
		posture, err := s.store.GetPosture(ctx, stackID, name)
		if err != nil {
			return err
		}
		posture.Rules = parseLines(r.FormValue("rules"))
		posture.UpdatedAt = now
		return s.store.UpdatePosture(ctx, posture)
	case "ipsets":
		ipset, err := s.store.GetIPSet(ctx, stackID, name)
		if err != nil {
			return err
		}
		ipset.Addresses = parseLines(r.FormValue("addresses"))
		ipset.UpdatedAt = now
		return s.store.UpdateIPSet(ctx, ipset)
	case "tests":
		test, err := s.store.GetACLTest(ctx, name)
		if err != nil {
			return err
		}
		test.Order = parseInt(r.FormValue("order"), test.Order)
		test.Source = r.FormValue("src")
		test.Accept = parseLines(r.FormValue("accept"))
		test.Deny = parseLines(r.FormValue("deny"))
		test.UpdatedAt = now
		return s.store.UpdateACLTest(ctx, test)
	}
	return domain.ErrInvalidInput
}

// deleteResource deletes a resource.
func (s *Server) deleteResource(ctx context.Context, stackID, resourceType, name string) error {
	switch resourceType {
	case "groups":
		return s.store.DeleteGroup(ctx, stackID, name)
	case "tags":
		return s.store.DeleteTagOwner(ctx, stackID, name)
	case "hosts":
		return s.store.DeleteHost(ctx, stackID, name)
	case "acls":
		return s.store.DeleteACLRule(ctx, name)
	case "ssh":
		return s.store.DeleteSSHRule(ctx, name)
	case "grants":
		return s.store.DeleteGrant(ctx, name)
	case "autoapprovers":
		return s.store.DeleteAutoApprover(ctx, name)
	case "nodeattrs":
		return s.store.DeleteNodeAttr(ctx, name)
	case "postures":
		return s.store.DeletePosture(ctx, stackID, name)
	case "ipsets":
		return s.store.DeleteIPSet(ctx, stackID, name)
	case "tests":
		return s.store.DeleteACLTest(ctx, name)
	}
	return domain.ErrInvalidInput
}

// parseLines parses a multiline string into a slice.
func parseLines(s string) []string {
	if s == "" {
		return nil
	}
	lines := strings.Split(s, "\n")
	var result []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			result = append(result, line)
		}
	}
	return result
}
