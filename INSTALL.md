# Installation cookbook

This guide collects the platform-specific installation paths and gotchas for
`mcp-audit`. For the short product overview and quick start, see
[README.md](README.md).

## Choosing an install method

| Method | Best for | Notes |
| --- | --- | --- |
| Prebuilt binary | Production/operator installs | Use GitHub Releases. |
| Docker / GHCR | Containerized environments | Mount a data volume. |
| `go install` | Development/source installs | Requires Go 1.22+. |

## Prerequisites

- `mcp-audit` itself has no runtime dependency when installed from a prebuilt
  archive. Release binaries are statically linked with `CGO_ENABLED=0`.
- The stdio examples often launch an upstream MCP server via `npx`, which
  requires [Node.js](https://nodejs.org/) 18+ on `PATH`. This is only needed
  for that example upstream, not for `mcp-audit`.
- `AUDIT_SECRET` is recommended when signing audit entries. Prefer setting it
  through the environment instead of storing secrets in config files.

## Linux

Linux archives are published for `amd64` and `arm64`. Package-manager installs
through apt, yum, or dnf are not available today.

```bash
version=1.0.0
base="https://github.com/P4ST4S/mcp-audit/releases/download/v${version}"
curl -L -o mcp-audit.tar.gz \
  "${base}/mcp-audit_${version}_linux_amd64.tar.gz"
curl -L -o mcp-audit_checksums.txt \
  "${base}/mcp-audit_${version}_checksums.txt"
sha256sum -c mcp-audit_checksums.txt --ignore-missing
tar -xzf mcp-audit.tar.gz
./mcp-audit --version
```

On 64-bit ARM Linux, replace `linux_amd64` with `linux_arm64`.

Install it on your `PATH` system-wide:

```bash
sudo install -m 0755 mcp-audit /usr/local/bin/mcp-audit
mcp-audit --version
```

SELinux does not need a special policy for the default JSONL path today. If you
run with SQLite storage under an enforced SELinux context, verify that the data
directory allows the container or service user to create and lock the database
file.

## macOS

Use `darwin_arm64` for Apple Silicon and `darwin_amd64` for Intel Macs. A
Homebrew formula is not available today.

```bash
version=1.0.0
base="https://github.com/P4ST4S/mcp-audit/releases/download/v${version}"
curl -L -o mcp-audit.tar.gz \
  "${base}/mcp-audit_${version}_darwin_arm64.tar.gz"
curl -L -o mcp-audit_checksums.txt \
  "${base}/mcp-audit_${version}_checksums.txt"
shasum -a 256 -c mcp-audit_checksums.txt --ignore-missing
tar -xzf mcp-audit.tar.gz
./mcp-audit --version
```

macOS Gatekeeper may quarantine the downloaded binary. If it is blocked, clear
the quarantine attribute:

```bash
xattr -d com.apple.quarantine ./mcp-audit
```

Install it on your `PATH`:

```bash
sudo install -m 0755 mcp-audit /usr/local/bin/mcp-audit
mcp-audit --version
```

## Windows

Windows builds are published as `.zip` archives for `amd64`. There is no
`windows_arm64` build today; on Windows on ARM, run the `amd64` binary under
emulation or build from source with Go.

```powershell
$version = "1.0.0"
$base = "https://github.com/P4ST4S/mcp-audit/releases/download/v$version"

Invoke-WebRequest `
  -Uri "$base/mcp-audit_$($version)_windows_amd64.zip" `
  -OutFile "mcp-audit.zip"
Invoke-WebRequest `
  -Uri "$base/mcp-audit_$($version)_checksums.txt" `
  -OutFile "mcp-audit_checksums.txt"

$line = Select-String -Path mcp-audit_checksums.txt -Pattern "windows_amd64.zip"
$expected = ($line.Line -split '\s+')[0].ToLower()
$actual   = (Get-FileHash -Algorithm SHA256 mcp-audit.zip).Hash.ToLower()
if ($actual -ne $expected) {
  throw "Checksum mismatch: expected $expected, got $actual"
}

Expand-Archive -Path mcp-audit.zip -DestinationPath . -Force
.\mcp-audit.exe --version
```

To make `mcp-audit` available in every new terminal, move `mcp-audit.exe` to a
directory on your user `PATH`:

```powershell
$dest = "$env:LOCALAPPDATA\Programs\mcp-audit"
New-Item -ItemType Directory -Force -Path $dest | Out-Null
Move-Item -Force .\mcp-audit.exe "$dest\mcp-audit.exe"
$currentPath = [Environment]::GetEnvironmentVariable("Path", "User")
[Environment]::SetEnvironmentVariable("Path", "$currentPath;$dest", "User")

# Open a new terminal, then:
mcp-audit --version
```

Windows Defender SmartScreen may warn on first run because the binary is new to
the machine. Verify the checksum first, then choose the "More info" prompt only
if the checksum matches the published release file.

## Docker / GHCR

The published GHCR image is intended for containerized environments and runs as
a non-root user. Mount a writable volume at `/data` so audit output survives
container restarts.

```bash
docker run --rm \
  -e AUDIT_SECRET=change-me \
  -v "$PWD/audit-data:/data" \
  ghcr.io/p4st4s/mcp-audit:v1.0.0 \
  --version
```

For a local HTTP proxy with the example stack, use Docker Compose:

```bash
docker compose up --build
```

The compose file starts `mcp-audit` and a sample filesystem MCP server. The
dashboard is available at `http://127.0.0.1:9090` by default, and Prometheus
metrics are available at `http://localhost:9091/metrics`.

## From source

Use Go 1.22 or newer. `go install` is the simplest source-based install for a
released version:

```bash
go install github.com/P4ST4S/mcp-audit/cmd/mcp-audit@v1.0.0
mcp-audit --version
```

Pin the version instead of using `@latest` when you need reproducible installs.

For local development, clone and build the repository:

```bash
git clone https://github.com/P4ST4S/mcp-audit.git
cd mcp-audit
go build ./cmd/mcp-audit
./mcp-audit --version
```

## Verifying the install

`mcp-audit --version` prints release metadata. Release binaries should include a
version with a `v` prefix, plus commit and build date when available.

For release archives, download `mcp-audit_<version>_checksums.txt` from the same
release and verify the archive before extracting it. Linux commonly uses
`sha256sum`, macOS uses `shasum -a 256`, and Windows can use `Get-FileHash` as
shown above.

## Troubleshooting

### Port already bound

HTTP mode uses proxy port `4422` by default. The dashboard uses `9090`, and
Prometheus metrics use `9091`.

```bash
mcp-audit --transport http --upstream http://localhost:8080 --port 4423
```

### `AUDIT_SECRET` missing

Unsigned audit entries are possible, but production deployments should set
`AUDIT_SECRET` so audit rows can be signed. Keep the value outside config files:

```bash
export AUDIT_SECRET="$(openssl rand -hex 32)"
```

On PowerShell:

```powershell
$env:AUDIT_SECRET = -join (
  (1..32) | ForEach-Object { '{0:x2}' -f (Get-Random -Max 256) }
)
```

### Upstream not reachable

Check the `--upstream` command or URL first. For stdio mode, make sure any
upstream binary such as `npx` is installed and available on `PATH`. For HTTP
mode, confirm the upstream server is reachable from the same host or container
network.

Increase logging while debugging:

```bash
mcp-audit --log-level debug --transport http --upstream http://localhost:8080
```
