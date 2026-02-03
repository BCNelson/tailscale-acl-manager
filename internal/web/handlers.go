package web

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/bcnelson/tailscale-acl-manager/internal/domain"
	"github.com/go-chi/chi/v5"
)

// handleLoginPage renders the login page.
func (s *Server) handleLoginPage(w http.ResponseWriter, r *http.Request) {
	data := PageData{
		Title: "Login",
	}

	// Check for flash message in query params
	if msg := r.URL.Query().Get("error"); msg != "" {
		data.Flash = &FlashMessage{Type: "error", Message: msg}
	}

	s.render(w, "base-noauth", "login", data)
}

// handleLogin processes the login form.
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/login?error=Invalid+form+data", http.StatusSeeOther)
		return
	}

	apiKey := r.FormValue("api_key")
	if apiKey == "" {
		http.Redirect(w, r, "/login?error=API+key+required", http.StatusSeeOther)
		return
	}

	ctx := r.Context()

	// Check if we have any API keys
	keyCount, err := s.store.CountAPIKeys(ctx)
	if err != nil {
		http.Redirect(w, r, "/login?error=Server+error", http.StatusSeeOther)
		return
	}

	// Validate the API key
	isValid := false

	// If no keys exist and bootstrap key is set, allow bootstrap key
	if keyCount == 0 && s.bootstrapKey != "" {
		if subtle.ConstantTimeCompare([]byte(apiKey), []byte(s.bootstrapKey)) == 1 {
			isValid = true
		}
	}

	// If not bootstrap, validate against stored keys
	if !isValid {
		keyHash := hashAPIKey(apiKey)
		_, err := s.store.GetAPIKeyByHash(ctx, keyHash)
		if err == nil {
			isValid = true
		}
	}

	if !isValid {
		http.Redirect(w, r, "/login?error=Invalid+API+key", http.StatusSeeOther)
		return
	}

	// Set session cookie and redirect
	setSessionCookie(w, apiKey)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// handleLogout clears the session and redirects to login.
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	clearSessionCookie(w)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// DashboardData holds data for the dashboard page.
type DashboardData struct {
	Stacks        []*domain.Stack
	StackCount    int
	LatestVersion *domain.PolicyVersion
	SyncStatus    string
}

// handleDashboard renders the dashboard page.
func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	stacks, err := s.store.ListStacks(ctx)
	if err != nil {
		s.renderError(w, "Failed to load stacks", http.StatusInternalServerError)
		return
	}

	latestVersion, _ := s.store.GetLatestPolicyVersion(ctx)

	syncStatus := "No sync yet"
	if latestVersion != nil {
		switch latestVersion.PushStatus {
		case "success":
			syncStatus = "Synced"
		case "failed":
			syncStatus = "Failed"
		case "pending":
			syncStatus = "Pending"
		}
	}

	data := PageData{
		Title:  "Dashboard",
		Active: "dashboard",
		Content: DashboardData{
			Stacks:        stacks,
			StackCount:    len(stacks),
			LatestVersion: latestVersion,
			SyncStatus:    syncStatus,
		},
	}

	s.render(w, "base", "dashboard", data)
}

// StacksListData holds data for the stacks list page.
type StacksListData struct {
	Stacks []*domain.Stack
}

// handleStacksList renders the stacks list page.
func (s *Server) handleStacksList(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	stacks, err := s.store.ListStacks(ctx)
	if err != nil {
		s.renderError(w, "Failed to load stacks", http.StatusInternalServerError)
		return
	}

	data := PageData{
		Title:  "Stacks",
		Active: "stacks",
		Content: StacksListData{
			Stacks: stacks,
		},
	}

	s.render(w, "base", "stacks_list", data)
}

// StackFormData holds data for stack create/edit form.
type StackFormData struct {
	Stack  *domain.Stack
	IsEdit bool
}

// handleStackForm renders the new stack form.
func (s *Server) handleStackForm(w http.ResponseWriter, r *http.Request) {
	data := PageData{
		Title: "New Stack",
		Content: StackFormData{
			Stack:  &domain.Stack{Priority: 100},
			IsEdit: false,
		},
	}
	s.renderFragment(w, "stack_form", data)
}

// handleStackCreate creates a new stack.
func (s *Server) handleStackCreate(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.renderError(w, "Invalid form data", http.StatusBadRequest)
		return
	}

	ctx := r.Context()

	stack := &domain.Stack{
		ID:          generateID(),
		Name:        r.FormValue("name"),
		Description: r.FormValue("description"),
		Priority:    parseInt(r.FormValue("priority"), 100),
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	if stack.Name == "" {
		s.renderError(w, "Name is required", http.StatusBadRequest)
		return
	}

	if err := s.store.CreateStack(ctx, stack); err != nil {
		if err == domain.ErrAlreadyExists {
			s.renderError(w, "Stack with this name already exists", http.StatusConflict)
			return
		}
		s.renderError(w, "Failed to create stack", http.StatusInternalServerError)
		return
	}

	// Redirect to stack detail
	w.Header().Set("HX-Redirect", "/stacks/"+stack.ID)
	w.WriteHeader(http.StatusOK)
}

// StackDetailData holds data for the stack detail page.
type StackDetailData struct {
	Stack         *domain.Stack
	ActiveTab     string
	ResourceCount map[string]int
}

// handleStackDetail renders the stack detail page.
func (s *Server) handleStackDetail(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	stackID := chi.URLParam(r, "id")

	stack, err := s.store.GetStack(ctx, stackID)
	if err != nil {
		if err == domain.ErrNotFound {
			s.renderError(w, "Stack not found", http.StatusNotFound)
			return
		}
		s.renderError(w, "Failed to load stack", http.StatusInternalServerError)
		return
	}

	// Get resource counts
	resourceCount := make(map[string]int)

	groups, _ := s.store.ListGroups(ctx, stackID)
	resourceCount["groups"] = len(groups)

	tags, _ := s.store.ListTagOwners(ctx, stackID)
	resourceCount["tags"] = len(tags)

	hosts, _ := s.store.ListHosts(ctx, stackID)
	resourceCount["hosts"] = len(hosts)

	acls, _ := s.store.ListACLRules(ctx, stackID)
	resourceCount["acls"] = len(acls)

	ssh, _ := s.store.ListSSHRules(ctx, stackID)
	resourceCount["ssh"] = len(ssh)

	grants, _ := s.store.ListGrants(ctx, stackID)
	resourceCount["grants"] = len(grants)

	autoapprovers, _ := s.store.ListAutoApprovers(ctx, stackID)
	resourceCount["autoapprovers"] = len(autoapprovers)

	nodeattrs, _ := s.store.ListNodeAttrs(ctx, stackID)
	resourceCount["nodeattrs"] = len(nodeattrs)

	postures, _ := s.store.ListPostures(ctx, stackID)
	resourceCount["postures"] = len(postures)

	ipsets, _ := s.store.ListIPSets(ctx, stackID)
	resourceCount["ipsets"] = len(ipsets)

	tests, _ := s.store.ListACLTests(ctx, stackID)
	resourceCount["tests"] = len(tests)

	activeTab := r.URL.Query().Get("tab")
	if activeTab == "" {
		activeTab = "groups"
	}

	data := PageData{
		Title:  stack.Name,
		Active: "stacks",
		Content: StackDetailData{
			Stack:         stack,
			ActiveTab:     activeTab,
			ResourceCount: resourceCount,
		},
	}

	s.render(w, "base", "stack_detail", data)
}

// handleStackEditForm renders the stack edit form.
func (s *Server) handleStackEditForm(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	stackID := chi.URLParam(r, "id")

	stack, err := s.store.GetStack(ctx, stackID)
	if err != nil {
		if err == domain.ErrNotFound {
			s.renderError(w, "Stack not found", http.StatusNotFound)
			return
		}
		s.renderError(w, "Failed to load stack", http.StatusInternalServerError)
		return
	}

	data := PageData{
		Title: "Edit Stack",
		Content: StackFormData{
			Stack:  stack,
			IsEdit: true,
		},
	}
	s.renderFragment(w, "stack_form", data)
}

// handleStackUpdate updates an existing stack.
func (s *Server) handleStackUpdate(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.renderError(w, "Invalid form data", http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	stackID := chi.URLParam(r, "id")

	stack, err := s.store.GetStack(ctx, stackID)
	if err != nil {
		if err == domain.ErrNotFound {
			s.renderError(w, "Stack not found", http.StatusNotFound)
			return
		}
		s.renderError(w, "Failed to load stack", http.StatusInternalServerError)
		return
	}

	stack.Name = r.FormValue("name")
	stack.Description = r.FormValue("description")
	stack.Priority = parseInt(r.FormValue("priority"), stack.Priority)
	stack.UpdatedAt = time.Now()

	if stack.Name == "" {
		s.renderError(w, "Name is required", http.StatusBadRequest)
		return
	}

	if err := s.store.UpdateStack(ctx, stack); err != nil {
		s.renderError(w, "Failed to update stack", http.StatusInternalServerError)
		return
	}

	// Trigger sync
	s.syncService.TriggerSync()

	w.Header().Set("HX-Redirect", "/stacks/"+stack.ID)
	w.WriteHeader(http.StatusOK)
}

// handleStackDelete deletes a stack.
func (s *Server) handleStackDelete(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	stackID := chi.URLParam(r, "id")

	if err := s.store.DeleteStack(ctx, stackID); err != nil {
		if err == domain.ErrNotFound {
			s.renderError(w, "Stack not found", http.StatusNotFound)
			return
		}
		s.renderError(w, "Failed to delete stack", http.StatusInternalServerError)
		return
	}

	// Trigger sync
	s.syncService.TriggerSync()

	w.Header().Set("HX-Redirect", "/stacks")
	w.WriteHeader(http.StatusOK)
}

// PolicyPageData holds data for the policy page.
type PolicyPageData struct {
	Policy        *domain.TailscalePolicy
	PolicyJSON    string
	Versions      []*domain.PolicyVersion
	LatestVersion *domain.PolicyVersion
}

// handlePolicyPage renders the policy page.
func (s *Server) handlePolicyPage(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	policy, err := s.syncService.GetMergedPolicy(ctx)
	if err != nil {
		s.renderError(w, "Failed to load policy", http.StatusInternalServerError)
		return
	}

	policyJSON, _ := json.MarshalIndent(policy, "", "  ")

	versions, _ := s.store.ListPolicyVersions(ctx, 10, 0)
	latestVersion, _ := s.store.GetLatestPolicyVersion(ctx)

	data := PageData{
		Title:  "Policy",
		Active: "policy",
		Content: PolicyPageData{
			Policy:        policy,
			PolicyJSON:    string(policyJSON),
			Versions:      versions,
			LatestVersion: latestVersion,
		},
	}

	s.render(w, "base", "policy", data)
}

// handlePolicyPreview renders the policy preview fragment.
func (s *Server) handlePolicyPreview(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	policy, err := s.syncService.GetMergedPolicy(ctx)
	if err != nil {
		s.renderError(w, "Failed to load policy", http.StatusInternalServerError)
		return
	}

	policyJSON, _ := json.MarshalIndent(policy, "", "  ")

	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(`<div class="code-block"><pre class="json-highlight">`))
	w.Write(policyJSON)
	w.Write([]byte(`</pre></div>`))
}

// handlePolicyVersions renders the policy versions fragment.
func (s *Server) handlePolicyVersions(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	versions, _ := s.store.ListPolicyVersions(ctx, 20, 0)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	if len(versions) == 0 {
		w.Write([]byte(`<div class="empty-state"><p>No versions yet.</p></div>`))
		return
	}

	var buf bytes.Buffer
	buf.WriteString(`<table><thead><tr><th>Version</th><th>Status</th><th>Time</th><th class="text-right">Actions</th></tr></thead><tbody>`)
	for _, v := range versions {
		buf.WriteString(`<tr><td>#`)
		buf.WriteString(strconv.Itoa(v.VersionNumber))
		buf.WriteString(`</td><td>`)
		switch v.PushStatus {
		case "success":
			buf.WriteString(`<span class="badge badge-success">Success</span>`)
		case "failed":
			buf.WriteString(`<span class="badge badge-danger">Failed</span>`)
		default:
			buf.WriteString(`<span class="badge badge-warning">Pending</span>`)
		}
		buf.WriteString(`</td><td class="text-muted">`)
		buf.WriteString(v.CreatedAt.Format("Jan 2, 15:04"))
		buf.WriteString(`</td><td class="table-actions">`)
		if v.PushStatus == "success" {
			buf.WriteString(`<button class="btn btn-sm btn-secondary" hx-post="/policy/rollback/`)
			buf.WriteString(v.ID)
			buf.WriteString(`" hx-swap="none" hx-confirm="Rollback to version #`)
			buf.WriteString(strconv.Itoa(v.VersionNumber))
			buf.WriteString(`?">Rollback</button>`)
		}
		buf.WriteString(`</td></tr>`)
	}
	buf.WriteString(`</tbody></table>`)
	w.Write(buf.Bytes())
}

// handlePolicySync triggers a policy sync.
func (s *Server) handlePolicySync(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	result, err := s.syncService.ForceSync(ctx)
	if err != nil {
		s.renderError(w, "Sync failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if result.Status == "failed" {
		s.renderError(w, "Sync failed: "+result.Error, http.StatusInternalServerError)
		return
	}

	w.Header().Set("HX-Redirect", "/policy")
	w.WriteHeader(http.StatusOK)
}

// handlePolicyRollback rolls back to a previous policy version.
func (s *Server) handlePolicyRollback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	versionID := chi.URLParam(r, "id")

	result, err := s.syncService.Rollback(ctx, versionID)
	if err != nil {
		s.renderError(w, "Rollback failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if result.Status == "failed" {
		s.renderError(w, "Rollback failed: "+result.Error, http.StatusInternalServerError)
		return
	}

	w.Header().Set("HX-Redirect", "/policy")
	w.WriteHeader(http.StatusOK)
}

// SettingsPageData holds data for the settings page.
type SettingsPageData struct {
	APIKeys []*domain.APIKey
}

// handleSettingsPage renders the settings page.
func (s *Server) handleSettingsPage(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	keys, err := s.store.ListAPIKeys(ctx)
	if err != nil {
		s.renderError(w, "Failed to load API keys", http.StatusInternalServerError)
		return
	}

	data := PageData{
		Title:  "Settings",
		Active: "settings",
		Content: SettingsPageData{
			APIKeys: keys,
		},
	}

	// Check for flash message
	if msg := r.URL.Query().Get("created"); msg != "" {
		data.Flash = &FlashMessage{
			Type:    "success",
			Message: "API key created. Make sure to copy it now - it won't be shown again: " + msg,
		}
	}

	s.render(w, "base", "settings", data)
}

// handleAPIKeyCreate creates a new API key.
func (s *Server) handleAPIKeyCreate(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.renderError(w, "Invalid form data", http.StatusBadRequest)
		return
	}

	ctx := r.Context()

	name := r.FormValue("name")
	if name == "" {
		s.renderError(w, "Name is required", http.StatusBadRequest)
		return
	}

	key, hash, prefix, err := generateAPIKeyPair()
	if err != nil {
		s.renderError(w, "Failed to generate key", http.StatusInternalServerError)
		return
	}

	apiKey := &domain.APIKey{
		ID:        generateID(),
		Name:      name,
		KeyHash:   hash,
		KeyPrefix: prefix,
		CreatedAt: time.Now(),
	}

	if err := s.store.CreateAPIKey(ctx, apiKey); err != nil {
		s.renderError(w, "Failed to create API key", http.StatusInternalServerError)
		return
	}

	// Redirect with the key shown once
	w.Header().Set("HX-Redirect", "/settings?created="+key)
	w.WriteHeader(http.StatusOK)
}

// handleAPIKeyDelete deletes an API key.
func (s *Server) handleAPIKeyDelete(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	keyID := chi.URLParam(r, "id")

	if err := s.store.DeleteAPIKey(ctx, keyID); err != nil {
		if err == domain.ErrNotFound {
			s.renderError(w, "API key not found", http.StatusNotFound)
			return
		}
		s.renderError(w, "Failed to delete API key", http.StatusInternalServerError)
		return
	}

	w.Header().Set("HX-Redirect", "/settings")
	w.WriteHeader(http.StatusOK)
}

// render renders a full page using the base template.
// page is the page name (e.g., "login", "dashboard", "stacks_list")
// base is the base template to use ("base" or "base-noauth")
func (s *Server) render(w http.ResponseWriter, base, page string, data PageData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	tmpl, ok := s.templates[page]
	if !ok {
		http.Error(w, "Template not found: "+page, http.StatusInternalServerError)
		return
	}

	err := tmpl.ExecuteTemplate(w, base, data)
	if err != nil {
		http.Error(w, "Template error: "+err.Error(), http.StatusInternalServerError)
	}
}

// renderFragment renders just the content block for htmx requests.
// page is the page name (e.g., "stack_form", "resource_form")
func (s *Server) renderFragment(w http.ResponseWriter, page string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	tmpl, ok := s.templates[page]
	if !ok {
		http.Error(w, "Template not found: "+page, http.StatusInternalServerError)
		return
	}

	err := tmpl.ExecuteTemplate(w, "content", data)
	if err != nil {
		http.Error(w, "Template error: "+err.Error(), http.StatusInternalServerError)
	}
}

// renderError renders an error message.
func (s *Server) renderError(w http.ResponseWriter, message string, status int) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	w.Write([]byte(`<div class="flash flash-error">` + message + `</div>`))
}
