package web

import (
	"embed"
	"html/template"
	"io/fs"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/bcnelson/tailscale-acl-manager/internal/service"
	"github.com/bcnelson/tailscale-acl-manager/internal/storage"
	"github.com/go-chi/chi/v5"
)

//go:embed templates/* static/*
var content embed.FS

// Server holds dependencies for web handlers.
type Server struct {
	store        storage.Storage
	syncService  *service.SyncService
	bootstrapKey string
	templates    map[string]*template.Template
	funcMap      template.FuncMap
}

// NewRouter creates a new web router with all routes configured.
func NewRouter(store storage.Storage, syncService *service.SyncService, bootstrapKey string) http.Handler {
	s := &Server{
		store:        store,
		syncService:  syncService,
		bootstrapKey: bootstrapKey,
	}

	// Parse all templates
	s.templates = s.parseTemplates()

	r := chi.NewRouter()

	// Static files
	staticFS, _ := fs.Sub(content, "static")
	r.Handle("/static/*", http.StripPrefix("/static/", http.FileServer(http.FS(staticFS))))

	// Public routes
	r.Get("/login", s.handleLoginPage)
	r.Post("/login", s.handleLogin)
	r.Get("/logout", s.handleLogout)

	// Protected routes (require session)
	r.Group(func(r chi.Router) {
		r.Use(s.sessionAuth)

		// Dashboard
		r.Get("/", s.handleDashboard)

		// Stacks
		r.Get("/stacks", s.handleStacksList)
		r.Get("/stacks/new", s.handleStackForm)
		r.Post("/stacks", s.handleStackCreate)
		r.Get("/stacks/{id}", s.handleStackDetail)
		r.Get("/stacks/{id}/edit", s.handleStackEditForm)
		r.Put("/stacks/{id}", s.handleStackUpdate)
		r.Delete("/stacks/{id}", s.handleStackDelete)

		// Resource routes (generic for all types)
		r.Get("/stacks/{id}/{resource}", s.handleResourceList)
		r.Get("/stacks/{id}/{resource}/new", s.handleResourceForm)
		r.Post("/stacks/{id}/{resource}", s.handleResourceCreate)
		r.Get("/stacks/{id}/{resource}/{name}/edit", s.handleResourceEditForm)
		r.Put("/stacks/{id}/{resource}/{name}", s.handleResourceUpdate)
		r.Delete("/stacks/{id}/{resource}/{name}", s.handleResourceDelete)

		// Policy
		r.Get("/policy", s.handlePolicyPage)
		r.Get("/policy/preview", s.handlePolicyPreview)
		r.Get("/policy/versions", s.handlePolicyVersions)
		r.Post("/policy/sync", s.handlePolicySync)
		r.Post("/policy/rollback/{id}", s.handlePolicyRollback)

		// Settings
		r.Get("/settings", s.handleSettingsPage)
		r.Post("/settings/keys", s.handleAPIKeyCreate)
		r.Delete("/settings/keys/{id}", s.handleAPIKeyDelete)
	})

	return r
}

// parseTemplates parses all templates with custom functions.
func (s *Server) parseTemplates() map[string]*template.Template {
	s.funcMap = template.FuncMap{
		"join":         strings.Join,
		"contains":     strings.Contains,
		"hasPrefix":    strings.HasPrefix,
		"trimPrefix":   strings.TrimPrefix,
		"lower":        strings.ToLower,
		"dict":         dict,
		"safeHTML":     safeHTML,
		"safeHTMLAttr": safeHTMLAttr,
		"json":         jsonMarshal,
	}

	templates := make(map[string]*template.Template)

	// Read base template and components
	baseContent, _ := content.ReadFile("templates/base.html")
	navContent, _ := content.ReadFile("templates/components/nav.html")
	flashContent, _ := content.ReadFile("templates/components/flash.html")
	modalContent, _ := content.ReadFile("templates/components/modal.html")

	// Combine base with components
	baseWithComponents := string(baseContent) + string(navContent) + string(flashContent) + string(modalContent)

	// Parse each page template separately with the base
	pageFiles, _ := fs.Glob(content, "templates/pages/*.html")
	for _, pagePath := range pageFiles {
		pageName := filepath.Base(pagePath)
		pageName = strings.TrimSuffix(pageName, ".html")

		pageContent, _ := content.ReadFile(pagePath)

		// Create new template for this page
		tmpl := template.New(pageName).Funcs(s.funcMap)
		tmpl, err := tmpl.Parse(baseWithComponents + string(pageContent))
		if err != nil {
			panic("failed to parse template " + pageName + ": " + err.Error())
		}

		templates[pageName] = tmpl
	}

	return templates
}

// dict creates a map from key-value pairs for use in templates.
func dict(values ...any) map[string]any {
	if len(values)%2 != 0 {
		return nil
	}
	m := make(map[string]any, len(values)/2)
	for i := 0; i < len(values); i += 2 {
		key, ok := values[i].(string)
		if !ok {
			continue
		}
		m[key] = values[i+1]
	}
	return m
}

// safeHTML marks a string as safe HTML to prevent escaping.
func safeHTML(s string) template.HTML {
	return template.HTML(s) //nolint:gosec
}

// safeHTMLAttr marks a string as a safe HTML attribute value to prevent escaping.
func safeHTMLAttr(s string) template.HTMLAttr {
	return template.HTMLAttr(s) //nolint:gosec
}

// jsonMarshal converts a value to JSON string for templates.
func jsonMarshal(v any) string {
	if v == nil {
		return ""
	}
	switch val := v.(type) {
	case []string:
		if len(val) == 0 {
			return ""
		}
		return strings.Join(val, "\n")
	case string:
		return val
	default:
		return ""
	}
}

// PageData holds common data passed to all page templates.
type PageData struct {
	Title   string
	Active  string // Current nav item
	Flash   *FlashMessage
	Content any
}

// FlashMessage represents a flash message.
type FlashMessage struct {
	Type    string // "success", "error", "info"
	Message string
}
