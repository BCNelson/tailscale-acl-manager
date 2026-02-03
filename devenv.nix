{ pkgs, lib, config, ... }:

{
  languages.go.enable = true;

  packages = with pkgs; [
    gotools
    golangci-lint
    delve
    git
    just
    jq
    curl
    gcc  # Required for CGO/sqlite
  ];

  env = {
    GOPATH = "${config.env.DEVENV_STATE}/go";
    GOCACHE = "${config.env.DEVENV_STATE}/go-cache";
    GOMODCACHE = "${config.env.DEVENV_STATE}/go-mod-cache";
    CGO_ENABLED = "1";  # Required for go-sqlite3
  };

  enterShell = ''
    echo "Tailscale ACL Manager Development Environment"
    echo "Go version: $(go version | cut -d' ' -f3)"
    echo ""
    echo "Available commands (run 'just' to see all):"
    echo "  just dev    - Run server with file shim"
    echo "  just test   - Run all tests"
    echo "  just build  - Build binary"
  '';

  git-hooks.hooks = {
    gofmt.enable = true;
    govet.enable = true;
    golangci-lint.enable = true;
  };
}
