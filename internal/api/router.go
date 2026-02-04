package api

import (
	"net/http"

	"github.com/bcnelson/tailscale-acl-manager/internal/api/handler"
	"github.com/bcnelson/tailscale-acl-manager/internal/api/middleware"
	"github.com/bcnelson/tailscale-acl-manager/internal/config"
	"github.com/bcnelson/tailscale-acl-manager/internal/service"
	"github.com/bcnelson/tailscale-acl-manager/internal/storage"
	"github.com/bcnelson/tailscale-acl-manager/internal/web"
	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
)

// NewRouter creates a new HTTP router with all routes configured.
func NewRouter(
	store storage.Storage,
	syncService *service.SyncService,
	bootstrapKey string,
	oidcConfig *config.OIDCConfig,
	oidcComponents *web.OIDCComponents,
) http.Handler {
	r := chi.NewRouter()

	// Global middleware
	r.Use(chimw.Recoverer)
	r.Use(middleware.Logging)

	// Health check (no auth required)
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	})

	// Mount web UI (no Content-Type middleware - serves HTML)
	webRouter := web.NewRouter(store, syncService, bootstrapKey, oidcConfig, oidcComponents)
	r.Mount("/", webRouter)

	// API routes (auth required, JSON Content-Type)
	r.Route("/api/v1", func(r chi.Router) {
		r.Use(middleware.ContentType)
		r.Use(middleware.Auth(store, bootstrapKey))

		// API Keys
		keyHandler := handler.NewAPIKeyHandler(store)
		r.Post("/keys", keyHandler.Create)
		r.Get("/keys", keyHandler.List)
		r.Delete("/keys/{id}", keyHandler.Delete)

		// Stacks
		stackHandler := handler.NewStackHandler(store, syncService)
		r.Post("/stacks", stackHandler.Create)
		r.Get("/stacks", stackHandler.List)

		// Stack-level routes and nested resources
		r.Route("/stacks/{stack_id}", func(r chi.Router) {
			// Stack CRUD (using stack_id parameter)
			r.Get("/", stackHandler.Get)
			r.Put("/", stackHandler.Update)
			r.Delete("/", stackHandler.Delete)

			// Bulk state management
			r.Put("/state", stackHandler.ReplaceState)
			// Groups
			groupHandler := handler.NewGroupHandler(store, syncService)
			r.Post("/groups", groupHandler.Create)
			r.Get("/groups", groupHandler.List)
			r.Get("/groups/{name}", groupHandler.Get)
			r.Put("/groups/{name}", groupHandler.Update)
			r.Delete("/groups/{name}", groupHandler.Delete)

			// Tag Owners
			tagHandler := handler.NewTagOwnerHandler(store, syncService)
			r.Post("/tags", tagHandler.Create)
			r.Get("/tags", tagHandler.List)
			r.Get("/tags/{tag}", tagHandler.Get)
			r.Put("/tags/{tag}", tagHandler.Update)
			r.Delete("/tags/{tag}", tagHandler.Delete)

			// Hosts
			hostHandler := handler.NewHostHandler(store, syncService)
			r.Post("/hosts", hostHandler.Create)
			r.Get("/hosts", hostHandler.List)
			r.Get("/hosts/{name}", hostHandler.Get)
			r.Put("/hosts/{name}", hostHandler.Update)
			r.Delete("/hosts/{name}", hostHandler.Delete)

			// ACL Rules
			aclHandler := handler.NewACLHandler(store, syncService)
			r.Post("/acls", aclHandler.Create)
			r.Get("/acls", aclHandler.List)
			r.Get("/acls/{id}", aclHandler.Get)
			r.Put("/acls/{id}", aclHandler.Update)
			r.Delete("/acls/{id}", aclHandler.Delete)

			// SSH Rules
			sshHandler := handler.NewSSHHandler(store, syncService)
			r.Post("/ssh", sshHandler.Create)
			r.Get("/ssh", sshHandler.List)
			r.Get("/ssh/{id}", sshHandler.Get)
			r.Put("/ssh/{id}", sshHandler.Update)
			r.Delete("/ssh/{id}", sshHandler.Delete)

			// Grants
			grantHandler := handler.NewGrantHandler(store, syncService)
			r.Post("/grants", grantHandler.Create)
			r.Get("/grants", grantHandler.List)
			r.Get("/grants/{id}", grantHandler.Get)
			r.Put("/grants/{id}", grantHandler.Update)
			r.Delete("/grants/{id}", grantHandler.Delete)

			// Auto Approvers
			autoApproverHandler := handler.NewAutoApproverHandler(store, syncService)
			r.Post("/autoapprovers", autoApproverHandler.Create)
			r.Get("/autoapprovers", autoApproverHandler.List)
			r.Get("/autoapprovers/{id}", autoApproverHandler.Get)
			r.Put("/autoapprovers/{id}", autoApproverHandler.Update)
			r.Delete("/autoapprovers/{id}", autoApproverHandler.Delete)

			// Node Attributes
			nodeAttrHandler := handler.NewNodeAttrHandler(store, syncService)
			r.Post("/nodeattrs", nodeAttrHandler.Create)
			r.Get("/nodeattrs", nodeAttrHandler.List)
			r.Get("/nodeattrs/{id}", nodeAttrHandler.Get)
			r.Put("/nodeattrs/{id}", nodeAttrHandler.Update)
			r.Delete("/nodeattrs/{id}", nodeAttrHandler.Delete)

			// Postures
			postureHandler := handler.NewPostureHandler(store, syncService)
			r.Post("/postures", postureHandler.Create)
			r.Get("/postures", postureHandler.List)
			r.Get("/postures/{name}", postureHandler.Get)
			r.Put("/postures/{name}", postureHandler.Update)
			r.Delete("/postures/{name}", postureHandler.Delete)

			// IP Sets
			ipsetHandler := handler.NewIPSetHandler(store, syncService)
			r.Post("/ipsets", ipsetHandler.Create)
			r.Get("/ipsets", ipsetHandler.List)
			r.Get("/ipsets/{name}", ipsetHandler.Get)
			r.Put("/ipsets/{name}", ipsetHandler.Update)
			r.Delete("/ipsets/{name}", ipsetHandler.Delete)

			// ACL Tests
			testHandler := handler.NewACLTestHandler(store, syncService)
			r.Post("/tests", testHandler.Create)
			r.Get("/tests", testHandler.List)
			r.Get("/tests/{id}", testHandler.Get)
			r.Put("/tests/{id}", testHandler.Update)
			r.Delete("/tests/{id}", testHandler.Delete)
		})

		// Policy management
		policyHandler := handler.NewPolicyHandler(store, syncService)
		r.Get("/policy", policyHandler.Get)
		r.Get("/policy/preview", policyHandler.Preview)
		r.Post("/policy/sync", policyHandler.Sync)
		r.Get("/policy/versions", policyHandler.ListVersions)
		r.Post("/policy/rollback/{id}", policyHandler.Rollback)
	})

	return r
}
