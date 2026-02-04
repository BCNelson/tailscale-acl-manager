package handler

import (
	"fmt"
	"net/http"
	"time"

	"github.com/bcnelson/tailscale-acl-manager/internal/domain"
)

// ETaggable is an interface for resources that can generate ETags.
type ETaggable interface {
	GetID() string
	GetUpdatedAt() time.Time
}

// GenerateETag generates an ETag for a resource based on its ID and updated_at timestamp.
// Format: "<resource_type>-<id>-<updated_at_unix_nano>"
func GenerateETag(resourceType, id string, updatedAt time.Time) string {
	return fmt.Sprintf(`"%s-%s-%d"`, resourceType, id, updatedAt.UnixNano())
}

// SetETagHeader sets the ETag header on the response.
func SetETagHeader(w http.ResponseWriter, resourceType, id string, updatedAt time.Time) {
	etag := GenerateETag(resourceType, id, updatedAt)
	w.Header().Set("ETag", etag)
}

// CheckIfMatch checks if the If-Match header matches the current ETag.
// Returns true if:
//   - No If-Match header is present (ETag checking is optional)
//   - The If-Match header matches the current ETag
//
// Returns false if the If-Match header is present but doesn't match.
func CheckIfMatch(r *http.Request, resourceType, id string, updatedAt time.Time) bool {
	ifMatch := r.Header.Get("If-Match")
	if ifMatch == "" {
		// No If-Match header, allow the request (ETag is optional)
		return true
	}

	currentETag := GenerateETag(resourceType, id, updatedAt)
	return ifMatch == currentETag
}

// RespondPreconditionFailed writes a 412 Precondition Failed response.
func RespondPreconditionFailed(w http.ResponseWriter, resourceType, id string, updatedAt time.Time) {
	currentETag := GenerateETag(resourceType, id, updatedAt)
	respondStandardError(w, http.StatusPreconditionFailed, domain.ErrCodePreconditionFailed,
		"resource has been modified", "", map[string]any{
			"currentETag": currentETag,
		})
}

// Group ETag helpers
func SetGroupETag(w http.ResponseWriter, group *domain.Group) {
	SetETagHeader(w, "group", group.ID, group.UpdatedAt)
}

func CheckGroupIfMatch(r *http.Request, group *domain.Group) bool {
	return CheckIfMatch(r, "group", group.ID, group.UpdatedAt)
}

// TagOwner ETag helpers
func SetTagOwnerETag(w http.ResponseWriter, tagOwner *domain.TagOwner) {
	SetETagHeader(w, "tagowner", tagOwner.ID, tagOwner.UpdatedAt)
}

func CheckTagOwnerIfMatch(r *http.Request, tagOwner *domain.TagOwner) bool {
	return CheckIfMatch(r, "tagowner", tagOwner.ID, tagOwner.UpdatedAt)
}

// Host ETag helpers
func SetHostETag(w http.ResponseWriter, host *domain.Host) {
	SetETagHeader(w, "host", host.ID, host.UpdatedAt)
}

func CheckHostIfMatch(r *http.Request, host *domain.Host) bool {
	return CheckIfMatch(r, "host", host.ID, host.UpdatedAt)
}

// Posture ETag helpers
func SetPostureETag(w http.ResponseWriter, posture *domain.Posture) {
	SetETagHeader(w, "posture", posture.ID, posture.UpdatedAt)
}

func CheckPostureIfMatch(r *http.Request, posture *domain.Posture) bool {
	return CheckIfMatch(r, "posture", posture.ID, posture.UpdatedAt)
}

// IPSet ETag helpers
func SetIPSetETag(w http.ResponseWriter, ipset *domain.IPSet) {
	SetETagHeader(w, "ipset", ipset.ID, ipset.UpdatedAt)
}

func CheckIPSetIfMatch(r *http.Request, ipset *domain.IPSet) bool {
	return CheckIfMatch(r, "ipset", ipset.ID, ipset.UpdatedAt)
}

// ACLRule ETag helpers
func SetACLRuleETag(w http.ResponseWriter, rule *domain.ACLRule) {
	SetETagHeader(w, "acl", rule.ID, rule.UpdatedAt)
}

func CheckACLRuleIfMatch(r *http.Request, rule *domain.ACLRule) bool {
	return CheckIfMatch(r, "acl", rule.ID, rule.UpdatedAt)
}

// SSHRule ETag helpers
func SetSSHRuleETag(w http.ResponseWriter, rule *domain.SSHRule) {
	SetETagHeader(w, "ssh", rule.ID, rule.UpdatedAt)
}

func CheckSSHRuleIfMatch(r *http.Request, rule *domain.SSHRule) bool {
	return CheckIfMatch(r, "ssh", rule.ID, rule.UpdatedAt)
}

// Stack ETag helpers
func SetStackETag(w http.ResponseWriter, stack *domain.Stack) {
	SetETagHeader(w, "stack", stack.ID, stack.UpdatedAt)
}

func CheckStackIfMatch(r *http.Request, stack *domain.Stack) bool {
	return CheckIfMatch(r, "stack", stack.ID, stack.UpdatedAt)
}
