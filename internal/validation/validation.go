// Package validation provides validation functions for Tailscale ACL entities.
// The validation rules are based on Tailscale's own validation (CheckTag) from
// https://github.com/tailscale/tailscale/blob/main/tailcfg/tailcfg.go
package validation

import (
	"fmt"
	"net"
	"strings"
)

// isAlpha returns true if the byte is an ASCII letter.
func isAlpha(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

// isNum returns true if the byte is an ASCII digit.
func isNum(b byte) bool {
	return b >= '0' && b <= '9'
}

// isAlphaNum returns true if the byte is an ASCII letter or digit.
func isAlphaNum(b byte) bool {
	return isAlpha(b) || isNum(b)
}

// validatePrefixedEntity validates entities that follow the pattern prefix:identifier
// where identifier must start with a letter and contain only letters, numbers, or hyphens.
func validatePrefixedEntity(value, prefix, entityType string) error {
	identifier, ok := strings.CutPrefix(value, prefix)
	if !ok {
		return fmt.Errorf("%s must start with '%s'", entityType, prefix)
	}
	if identifier == "" {
		return fmt.Errorf("%s name must not be empty after '%s'", entityType, prefix)
	}
	if !isAlpha(identifier[0]) {
		return fmt.Errorf("%s name must start with a letter after '%s'", entityType, prefix)
	}
	for _, b := range []byte(identifier) {
		if !isAlpha(b) && !isNum(b) && b != '-' {
			return fmt.Errorf("%s names can only contain letters, numbers, or hyphens", entityType)
		}
	}
	return nil
}

// ValidateTagName validates a tag name per Tailscale rules.
// Tags must be in the format: tag:<identifier>
// where identifier starts with a letter and contains only letters, numbers, or hyphens.
func ValidateTagName(tag string) error {
	return validatePrefixedEntity(tag, "tag:", "tag")
}

// ValidateGroupName validates a group name per Tailscale rules.
// Groups must be in the format: group:<identifier>
// where identifier starts with a letter and contains only letters, numbers, or hyphens.
func ValidateGroupName(name string) error {
	return validatePrefixedEntity(name, "group:", "group")
}

// ValidateServiceName validates a service name per Tailscale rules.
// Services must be in the format: svc:<identifier>
// where identifier starts with a letter and contains only letters, numbers, or hyphens.
func ValidateServiceName(name string) error {
	return validatePrefixedEntity(name, "svc:", "service")
}

// ValidateIPSetName validates an IP set name per Tailscale rules.
// IP sets must be in the format: ipset:<identifier>
// where identifier starts with a letter and contains only letters, numbers, or hyphens.
func ValidateIPSetName(name string) error {
	return validatePrefixedEntity(name, "ipset:", "IP set")
}

// validAutogroups is the complete list of valid autogroup names from Tailscale's syntax reference.
var validAutogroups = map[string]bool{
	"autogroup:internet":      true,
	"autogroup:self":          true,
	"autogroup:owner":         true,
	"autogroup:admin":         true,
	"autogroup:member":        true,
	"autogroup:tagged":        true,
	"autogroup:auditor":       true,
	"autogroup:billing-admin": true,
	"autogroup:it-admin":      true,
	"autogroup:network-admin": true,
	"autogroup:nonroot":       true,
	"autogroup:shared":        true,
	"autogroup:danger-all":    true,
}

// ValidAutogroups returns the list of valid autogroup names.
func ValidAutogroups() []string {
	groups := make([]string, 0, len(validAutogroups))
	for g := range validAutogroups {
		groups = append(groups, g)
	}
	return groups
}

// ValidateAutogroup validates an autogroup name.
func ValidateAutogroup(ag string) error {
	if !strings.HasPrefix(ag, "autogroup:") {
		return fmt.Errorf("autogroup must start with 'autogroup:'")
	}
	if !validAutogroups[ag] {
		return fmt.Errorf("invalid autogroup: %s", ag)
	}
	return nil
}

// IsAutogroup returns true if the string is a valid autogroup.
func IsAutogroup(s string) bool {
	return validAutogroups[s]
}

// ValidateHostName validates a host alias name.
// Host names must start with a letter and contain only letters, numbers, or hyphens.
func ValidateHostName(name string) error {
	if name == "" {
		return fmt.Errorf("host name must not be empty")
	}
	if !isAlpha(name[0]) {
		return fmt.Errorf("host name must start with a letter")
	}
	for _, b := range []byte(name) {
		if !isAlpha(b) && !isNum(b) && b != '-' {
			return fmt.Errorf("host names can only contain letters, numbers, or hyphens")
		}
	}
	return nil
}

// ValidateHostAddress validates an IP address or CIDR notation.
func ValidateHostAddress(addr string) error {
	if addr == "" {
		return fmt.Errorf("address must not be empty")
	}
	// Try parsing as IP
	if ip := net.ParseIP(addr); ip != nil {
		return nil
	}
	// Try parsing as CIDR
	if _, _, err := net.ParseCIDR(addr); err == nil {
		return nil
	}
	return fmt.Errorf("must be a valid IP address or CIDR")
}

// ValidateEmail validates an email-like user identifier.
// Tailscale accepts emails in the form user@domain or user@provider (e.g., user@github).
func ValidateEmail(email string) error {
	if email == "" {
		return fmt.Errorf("email must not be empty")
	}
	atIndex := strings.Index(email, "@")
	if atIndex < 1 {
		return fmt.Errorf("email must contain '@' after at least one character")
	}
	if atIndex == len(email)-1 {
		return fmt.Errorf("email must have domain after '@'")
	}
	return nil
}

// ValidateGroupMember validates a group member.
// Valid members are: email addresses, group:name, or tag:name.
func ValidateGroupMember(member string) error {
	if member == "" {
		return fmt.Errorf("member must not be empty")
	}

	// Check if it's a group reference
	if strings.HasPrefix(member, "group:") {
		return ValidateGroupName(member)
	}

	// Check if it's a tag reference
	if strings.HasPrefix(member, "tag:") {
		return ValidateTagName(member)
	}

	// Otherwise it must be an email
	return ValidateEmail(member)
}

// ValidateTagOwner validates a tag owner.
// Valid owners are: email addresses, group:name, or autogroup:name.
func ValidateTagOwner(owner string) error {
	if owner == "" {
		return fmt.Errorf("owner must not be empty")
	}

	// Check if it's a group reference
	if strings.HasPrefix(owner, "group:") {
		return ValidateGroupName(owner)
	}

	// Check if it's an autogroup reference
	if strings.HasPrefix(owner, "autogroup:") {
		return ValidateAutogroup(owner)
	}

	// Otherwise it must be an email
	return ValidateEmail(owner)
}

// ValidateACLSource validates an ACL rule source.
// Valid sources are: *, user email, group:name, tag:name, autogroup:name, host alias, or ipset:name.
func ValidateACLSource(src string) error {
	if src == "" {
		return fmt.Errorf("source must not be empty")
	}

	// Wildcard
	if src == "*" {
		return nil
	}

	// Group
	if strings.HasPrefix(src, "group:") {
		return ValidateGroupName(src)
	}

	// Tag
	if strings.HasPrefix(src, "tag:") {
		return ValidateTagName(src)
	}

	// Autogroup
	if strings.HasPrefix(src, "autogroup:") {
		return ValidateAutogroup(src)
	}

	// IP Set
	if strings.HasPrefix(src, "ipset:") {
		return ValidateIPSetName(src)
	}

	// IP address or CIDR
	if ip := net.ParseIP(src); ip != nil {
		return nil
	}
	if _, _, err := net.ParseCIDR(src); err == nil {
		return nil
	}

	// User email (contains @)
	if strings.Contains(src, "@") {
		return ValidateEmail(src)
	}

	// Assume it's a host alias - validate as hostname
	return ValidateHostName(src)
}

// ValidateACLDestination validates an ACL rule destination.
// Destinations are in the format: entity:ports (e.g., tag:server:22, group:dev:80,443, 10.0.0.0/8:*).
// Also supports svc:name for service references.
func ValidateACLDestination(dst string) error {
	if dst == "" {
		return fmt.Errorf("destination must not be empty")
	}

	// Wildcard
	if dst == "*" || dst == "*:*" {
		return nil
	}

	// Service destination (svc:name)
	if strings.HasPrefix(dst, "svc:") {
		// Services can have :port suffix or not
		parts := strings.SplitN(dst, ":", 3)
		if len(parts) >= 2 {
			svcName := "svc:" + parts[1]
			return ValidateServiceName(svcName)
		}
		return ValidateServiceName(dst)
	}

	// Try to parse as entity:port format
	// Find the last colon that separates entity from port
	lastColon := strings.LastIndex(dst, ":")
	if lastColon == -1 {
		// No port specified - could be host, IP, or CIDR
		if ip := net.ParseIP(dst); ip != nil {
			return nil
		}
		if _, _, err := net.ParseCIDR(dst); err == nil {
			return nil
		}
		// Assume it's a host alias
		return ValidateHostName(dst)
	}

	entity := dst[:lastColon]
	port := dst[lastColon+1:]

	// Validate the port portion
	if err := validatePort(port); err != nil {
		return fmt.Errorf("invalid port in destination: %w", err)
	}

	// Handle prefixed entities with their own colons (group:name, tag:name, etc.)
	if strings.HasPrefix(entity, "group:") {
		return ValidateGroupName(entity)
	}
	if strings.HasPrefix(entity, "tag:") {
		return ValidateTagName(entity)
	}
	if strings.HasPrefix(entity, "autogroup:") {
		return ValidateAutogroup(entity)
	}
	if strings.HasPrefix(entity, "ipset:") {
		return ValidateIPSetName(entity)
	}

	// IP address
	if ip := net.ParseIP(entity); ip != nil {
		return nil
	}

	// CIDR
	if _, _, err := net.ParseCIDR(entity); err == nil {
		return nil
	}

	// User email
	if strings.Contains(entity, "@") {
		return ValidateEmail(entity)
	}

	// Host alias
	return ValidateHostName(entity)
}

// validatePort validates a port specification.
// Valid formats: *, single port (22), port range (80-443), or comma-separated list.
func validatePort(port string) error {
	if port == "" {
		return fmt.Errorf("port must not be empty")
	}
	if port == "*" {
		return nil
	}

	// Check for comma-separated ports
	parts := strings.Split(port, ",")
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if err := validateSinglePort(p); err != nil {
			return err
		}
	}
	return nil
}

// validateSinglePort validates a single port or port range.
func validateSinglePort(port string) error {
	if port == "*" {
		return nil
	}

	// Check for range (e.g., 80-443)
	if strings.Contains(port, "-") {
		parts := strings.Split(port, "-")
		if len(parts) != 2 {
			return fmt.Errorf("invalid port range: %s", port)
		}
		for _, p := range parts {
			if !isValidPortNumber(p) {
				return fmt.Errorf("invalid port number: %s", p)
			}
		}
		return nil
	}

	if !isValidPortNumber(port) {
		return fmt.Errorf("invalid port number: %s", port)
	}
	return nil
}

// isValidPortNumber checks if a string is a valid port number (1-65535).
func isValidPortNumber(s string) bool {
	if s == "" {
		return false
	}
	num := 0
	for _, b := range []byte(s) {
		if !isNum(b) {
			return false
		}
		num = num*10 + int(b-'0')
		if num > 65535 {
			return false
		}
	}
	return num > 0 && num <= 65535
}

// ValidateSSHUser validates an SSH user specification.
// Valid formats: username, autogroup:nonroot, autogroup:root.
func ValidateSSHUser(user string) error {
	if user == "" {
		return fmt.Errorf("SSH user must not be empty")
	}

	// Autogroup references for SSH
	if strings.HasPrefix(user, "autogroup:") {
		if user == "autogroup:nonroot" {
			return nil
		}
		return fmt.Errorf("invalid SSH autogroup: %s (only autogroup:nonroot is allowed)", user)
	}

	// Simple username validation - alphanumeric and some special chars
	for _, b := range []byte(user) {
		if !isAlphaNum(b) && b != '-' && b != '_' && b != '.' {
			return fmt.Errorf("SSH username contains invalid character")
		}
	}
	return nil
}

// ValidateAutoApproverMatch validates the match field for an auto-approver.
// For routes type: must be a valid CIDR.
// For exitNode type: must be "*" (wildcard) or a tag reference.
func ValidateAutoApproverMatch(approverType, match string) error {
	if match == "" {
		return fmt.Errorf("match must not be empty")
	}

	switch approverType {
	case "routes":
		if _, _, err := net.ParseCIDR(match); err != nil {
			return fmt.Errorf("routes match must be a valid CIDR: %s", match)
		}
	case "exitNode":
		if match == "*" {
			return nil
		}
		if strings.HasPrefix(match, "tag:") {
			return ValidateTagName(match)
		}
		return fmt.Errorf("exitNode match must be '*' or a tag reference")
	default:
		return fmt.Errorf("invalid auto-approver type: %s", approverType)
	}
	return nil
}

// ValidateAutoApprover validates an auto-approver entry.
// Valid approvers are: tag:name, group:name, or autogroup:member.
func ValidateAutoApprover(approver string) error {
	if approver == "" {
		return fmt.Errorf("approver must not be empty")
	}

	if strings.HasPrefix(approver, "tag:") {
		return ValidateTagName(approver)
	}
	if strings.HasPrefix(approver, "group:") {
		return ValidateGroupName(approver)
	}
	if strings.HasPrefix(approver, "autogroup:") {
		return ValidateAutogroup(approver)
	}

	return fmt.Errorf("approver must be tag:, group:, or autogroup: reference")
}

// ValidateNodeAttrTarget validates a node attribute target.
// Valid targets are: *, group:name, tag:name, or user email.
func ValidateNodeAttrTarget(target string) error {
	if target == "" {
		return fmt.Errorf("target must not be empty")
	}

	if target == "*" {
		return nil
	}

	if strings.HasPrefix(target, "group:") {
		return ValidateGroupName(target)
	}
	if strings.HasPrefix(target, "tag:") {
		return ValidateTagName(target)
	}
	if strings.HasPrefix(target, "autogroup:") {
		return ValidateAutogroup(target)
	}
	if strings.Contains(target, "@") {
		return ValidateEmail(target)
	}

	return fmt.Errorf("target must be *, group:, tag:, autogroup:, or user email")
}
