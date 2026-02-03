package validation

import (
	"testing"
)

func TestValidateTagName(t *testing.T) {
	tests := []struct {
		name    string
		tag     string
		wantErr bool
	}{
		{"valid simple tag", "tag:server", false},
		{"valid tag with numbers", "tag:server1", false},
		{"valid tag with hyphen", "tag:prod-server", false},
		{"valid tag with mixed case", "tag:ProdServer", false},
		{"missing prefix", "server", true},
		{"wrong prefix", "group:server", true},
		{"empty after prefix", "tag:", true},
		{"starts with number", "tag:1server", true},
		{"starts with hyphen", "tag:-server", true},
		{"contains underscore", "tag:prod_server", true},
		{"contains space", "tag:prod server", true},
		{"contains dot", "tag:prod.server", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateTagName(tt.tag)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateTagName(%q) error = %v, wantErr %v", tt.tag, err, tt.wantErr)
			}
		})
	}
}

func TestValidateGroupName(t *testing.T) {
	tests := []struct {
		name    string
		group   string
		wantErr bool
	}{
		{"valid simple group", "group:developers", false},
		{"valid group with numbers", "group:team1", false},
		{"valid group with hyphen", "group:dev-team", false},
		{"missing prefix", "developers", true},
		{"wrong prefix", "tag:developers", true},
		{"empty after prefix", "group:", true},
		{"starts with number", "group:1team", true},
		{"contains underscore", "group:dev_team", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateGroupName(tt.group)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateGroupName(%q) error = %v, wantErr %v", tt.group, err, tt.wantErr)
			}
		})
	}
}

func TestValidateServiceName(t *testing.T) {
	tests := []struct {
		name    string
		svc     string
		wantErr bool
	}{
		{"valid service", "svc:web-server", false},
		{"valid service with numbers", "svc:api2", false},
		{"missing prefix", "web-server", true},
		{"wrong prefix", "tag:web-server", true},
		{"empty after prefix", "svc:", true},
		{"starts with number", "svc:2api", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateServiceName(tt.svc)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateServiceName(%q) error = %v, wantErr %v", tt.svc, err, tt.wantErr)
			}
		})
	}
}

func TestValidateIPSetName(t *testing.T) {
	tests := []struct {
		name    string
		ipset   string
		wantErr bool
	}{
		{"valid ipset", "ipset:office-ips", false},
		{"valid ipset with numbers", "ipset:office1", false},
		{"missing prefix", "office-ips", true},
		{"wrong prefix", "group:office-ips", true},
		{"empty after prefix", "ipset:", true},
		{"starts with number", "ipset:1office", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateIPSetName(tt.ipset)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateIPSetName(%q) error = %v, wantErr %v", tt.ipset, err, tt.wantErr)
			}
		})
	}
}

func TestValidateAutogroup(t *testing.T) {
	tests := []struct {
		name    string
		ag      string
		wantErr bool
	}{
		{"valid internet", "autogroup:internet", false},
		{"valid self", "autogroup:self", false},
		{"valid owner", "autogroup:owner", false},
		{"valid admin", "autogroup:admin", false},
		{"valid member", "autogroup:member", false},
		{"valid tagged", "autogroup:tagged", false},
		{"valid auditor", "autogroup:auditor", false},
		{"valid billing-admin", "autogroup:billing-admin", false},
		{"valid it-admin", "autogroup:it-admin", false},
		{"valid network-admin", "autogroup:network-admin", false},
		{"valid nonroot", "autogroup:nonroot", false},
		{"valid shared", "autogroup:shared", false},
		{"valid danger-all", "autogroup:danger-all", false},
		{"invalid autogroup", "autogroup:invalid", true},
		{"missing prefix", "internet", true},
		{"wrong prefix", "group:internet", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateAutogroup(tt.ag)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateAutogroup(%q) error = %v, wantErr %v", tt.ag, err, tt.wantErr)
			}
		})
	}
}

func TestValidateHostName(t *testing.T) {
	tests := []struct {
		name     string
		hostname string
		wantErr  bool
	}{
		{"valid simple name", "webserver", false},
		{"valid with numbers", "server1", false},
		{"valid with hyphen", "web-server", false},
		{"valid mixed case", "WebServer", false},
		{"empty name", "", true},
		{"starts with number", "1server", true},
		{"starts with hyphen", "-server", true},
		{"contains underscore", "web_server", true},
		{"contains dot", "web.server", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateHostName(tt.hostname)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateHostName(%q) error = %v, wantErr %v", tt.hostname, err, tt.wantErr)
			}
		})
	}
}

func TestValidateHostAddress(t *testing.T) {
	tests := []struct {
		name    string
		addr    string
		wantErr bool
	}{
		{"valid IPv4", "192.168.1.1", false},
		{"valid IPv6", "2001:db8::1", false},
		{"valid CIDR v4", "10.0.0.0/8", false},
		{"valid CIDR v6", "2001:db8::/32", false},
		{"empty", "", true},
		{"invalid IP", "999.999.999.999", true},
		{"hostname", "example.com", true},
		{"invalid CIDR", "10.0.0.0/99", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateHostAddress(tt.addr)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateHostAddress(%q) error = %v, wantErr %v", tt.addr, err, tt.wantErr)
			}
		})
	}
}

func TestValidateEmail(t *testing.T) {
	tests := []struct {
		name    string
		email   string
		wantErr bool
	}{
		{"valid email", "user@example.com", false},
		{"valid Tailscale format", "user@github", false},
		{"multiple dots", "user.name@example.co.uk", false},
		{"empty", "", true},
		{"no at", "userexample.com", true},
		{"at at start", "@example.com", true},
		{"at at end", "user@", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateEmail(tt.email)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateEmail(%q) error = %v, wantErr %v", tt.email, err, tt.wantErr)
			}
		})
	}
}

func TestValidateGroupMember(t *testing.T) {
	tests := []struct {
		name    string
		member  string
		wantErr bool
	}{
		{"valid email", "user@example.com", false},
		{"valid group ref", "group:developers", false},
		{"valid tag ref", "tag:server", false},
		{"empty", "", true},
		{"invalid group", "group:1invalid", true},
		{"invalid tag", "tag:_invalid", true},
		{"plain text", "notanemail", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateGroupMember(tt.member)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateGroupMember(%q) error = %v, wantErr %v", tt.member, err, tt.wantErr)
			}
		})
	}
}

func TestValidateTagOwner(t *testing.T) {
	tests := []struct {
		name    string
		owner   string
		wantErr bool
	}{
		{"valid email", "user@example.com", false},
		{"valid group ref", "group:admins", false},
		{"valid autogroup", "autogroup:admin", false},
		{"empty", "", true},
		{"invalid group", "group:1invalid", true},
		{"invalid autogroup", "autogroup:invalid", true},
		{"tag not allowed", "tag:server", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateTagOwner(tt.owner)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateTagOwner(%q) error = %v, wantErr %v", tt.owner, err, tt.wantErr)
			}
		})
	}
}

func TestValidateACLSource(t *testing.T) {
	tests := []struct {
		name    string
		src     string
		wantErr bool
	}{
		{"wildcard", "*", false},
		{"valid email", "user@example.com", false},
		{"valid group", "group:developers", false},
		{"valid tag", "tag:server", false},
		{"valid autogroup", "autogroup:member", false},
		{"valid ipset", "ipset:office", false},
		{"valid IP", "192.168.1.1", false},
		{"valid CIDR", "10.0.0.0/8", false},
		{"valid host alias", "webserver", false},
		{"empty", "", true},
		{"invalid group", "group:1invalid", true},
		{"invalid tag", "tag:_invalid", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateACLSource(tt.src)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateACLSource(%q) error = %v, wantErr %v", tt.src, err, tt.wantErr)
			}
		})
	}
}

func TestValidateACLDestination(t *testing.T) {
	tests := []struct {
		name    string
		dst     string
		wantErr bool
	}{
		{"wildcard", "*", false},
		{"wildcard with port", "*:*", false},
		{"tag with port", "tag:server:22", false},
		{"tag with port range", "tag:server:80-443", false},
		{"tag with multiple ports", "tag:server:22,80,443", false},
		{"tag with wildcard port", "tag:server:*", false},
		{"group with port", "group:dev:8080", false},
		{"IP with port", "192.168.1.1:22", false},
		{"CIDR with port", "10.0.0.0/8:*", false},
		{"host alias with port", "webserver:443", false},
		{"host alias without port", "webserver", false},
		{"service", "svc:web-server", false},
		{"autogroup with port", "autogroup:internet:443", false},
		{"empty", "", true},
		{"invalid port", "tag:server:99999", true},
		{"invalid tag", "tag:1invalid:22", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateACLDestination(tt.dst)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateACLDestination(%q) error = %v, wantErr %v", tt.dst, err, tt.wantErr)
			}
		})
	}
}

func TestValidateSSHUser(t *testing.T) {
	tests := []struct {
		name    string
		user    string
		wantErr bool
	}{
		{"valid username", "root", false},
		{"valid with numbers", "user1", false},
		{"valid with underscore", "test_user", false},
		{"valid with dot", "test.user", false},
		{"valid with hyphen", "test-user", false},
		{"valid nonroot autogroup", "autogroup:nonroot", false},
		{"empty", "", true},
		{"invalid autogroup", "autogroup:admin", true},
		{"invalid characters", "user@host", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateSSHUser(tt.user)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateSSHUser(%q) error = %v, wantErr %v", tt.user, err, tt.wantErr)
			}
		})
	}
}

func TestValidateAutoApproverMatch(t *testing.T) {
	tests := []struct {
		name         string
		approverType string
		match        string
		wantErr      bool
	}{
		{"routes valid CIDR", "routes", "10.0.0.0/8", false},
		{"routes valid CIDR v6", "routes", "2001:db8::/32", false},
		{"routes invalid", "routes", "invalid", true},
		{"routes IP not CIDR", "routes", "10.0.0.1", true},
		{"exitNode wildcard", "exitNode", "*", false},
		{"exitNode tag", "exitNode", "tag:exit-nodes", false},
		{"exitNode invalid tag", "exitNode", "tag:1invalid", true},
		{"exitNode invalid value", "exitNode", "group:exits", true},
		{"invalid type", "invalid", "*", true},
		{"empty match", "routes", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateAutoApproverMatch(tt.approverType, tt.match)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateAutoApproverMatch(%q, %q) error = %v, wantErr %v", tt.approverType, tt.match, err, tt.wantErr)
			}
		})
	}
}

func TestValidateAutoApprover(t *testing.T) {
	tests := []struct {
		name     string
		approver string
		wantErr  bool
	}{
		{"valid tag", "tag:admin-nodes", false},
		{"valid group", "group:admins", false},
		{"valid autogroup", "autogroup:member", false},
		{"empty", "", true},
		{"invalid tag", "tag:1invalid", true},
		{"invalid group", "group:_invalid", true},
		{"email not allowed", "user@example.com", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateAutoApprover(tt.approver)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateAutoApprover(%q) error = %v, wantErr %v", tt.approver, err, tt.wantErr)
			}
		})
	}
}

func TestValidateNodeAttrTarget(t *testing.T) {
	tests := []struct {
		name    string
		target  string
		wantErr bool
	}{
		{"wildcard", "*", false},
		{"valid group", "group:developers", false},
		{"valid tag", "tag:server", false},
		{"valid autogroup", "autogroup:member", false},
		{"valid email", "user@example.com", false},
		{"empty", "", true},
		{"invalid group", "group:1invalid", true},
		{"invalid format", "host:name", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateNodeAttrTarget(tt.target)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateNodeAttrTarget(%q) error = %v, wantErr %v", tt.target, err, tt.wantErr)
			}
		})
	}
}

func TestIsAutogroup(t *testing.T) {
	if !IsAutogroup("autogroup:internet") {
		t.Error("Expected autogroup:internet to be valid")
	}
	if IsAutogroup("autogroup:invalid") {
		t.Error("Expected autogroup:invalid to be invalid")
	}
	if IsAutogroup("group:something") {
		t.Error("Expected group:something to not be an autogroup")
	}
}

func TestValidAutogroups(t *testing.T) {
	groups := ValidAutogroups()
	if len(groups) != 13 {
		t.Errorf("Expected 13 autogroups, got %d", len(groups))
	}
}
