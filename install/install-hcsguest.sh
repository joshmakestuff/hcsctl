#!/bin/sh
# Installs the hcsguest agent and its systemd unit inside a Linux guest, then proves it runs.
#
# Usage:
#   ./install-hcsguest.sh -p /path/to/hcsguest       # local artifact
#   ./install-hcsguest.sh -v v0.4.0                  # download a pinned release
#   ./install-hcsguest.sh -p /path/to/hcsguest -s <sha256>
#
# Run as root inside a systemd-based guest. The download path needs curl and sha256sum. There is
# no "latest": use the tag of the host hcsctl.

set -eu

INSTALL_DIR=/opt/hcsguest
BIN="$INSTALL_DIR/hcsguest"
BACKUP="$INSTALL_DIR/hcsguest.bak"
UNIT=/etc/systemd/system/hcsguest.service
RELEASE_BASE=${RELEASE_BASE:-https://github.com/joshmakestuff/hcsctl/releases/download}
ASSET=hcsguest-linux-amd64

version=
path=
sha256=

usage() {
    echo "usage: install-hcsguest.sh -v <tag> | -p <artifact> [-s <sha256>]" >&2
    exit 64
}

while getopts 'v:p:s:h' opt; do
    case "$opt" in
        v) version=$OPTARG ;;
        p) path=$OPTARG ;;
        s) sha256=$OPTARG ;;
        h) usage ;;
        *) usage ;;
    esac
done
shift $((OPTIND - 1))

if [ $# -ne 0 ]; then usage; fi
if [ -n "$version" ] && [ -n "$path" ]; then
    echo "error: provide exactly one of -v (tag) or -p (local artifact)" >&2
    exit 64
fi
if [ -z "$version" ] && [ -z "$path" ]; then usage; fi
if [ "$(id -u)" -ne 0 ]; then
    echo "error: run as root" >&2
    exit 1
fi

token=${GH_TOKEN:-${GITHUB_TOKEN:-}}

rollback() {
    if [ -e "$BACKUP" ]; then
        systemctl stop hcsguest.service 2>/dev/null || true
        mv -f "$BACKUP" "$BIN"
        systemctl start hcsguest.service 2>/dev/null || true
        echo "rolled back to the prior install." >&2
    fi
}

staging=$(mktemp -d)
trap 'rm -rf "$staging"' EXIT
candidate=

# --- acquire ---
if [ -n "$path" ]; then
    candidate="$staging/$ASSET"
    cp "$path" "$candidate"
    if [ -n "$sha256" ]; then
        actual=$(sha256sum "$candidate" | awk '{print $1}')
        want=$(printf '%s' "$sha256" | tr 'A-F' 'a-f')
        if [ "$actual" != "$want" ]; then
            echo "error: SHA-256 mismatch for '$path'" >&2
            echo "  expected $want" >&2
            echo "  got      $actual" >&2
            exit 1
        fi
    fi
else
    if ! command -v curl >/dev/null 2>&1; then
        echo "error: curl is required for -v downloads; use -p instead" >&2
        exit 1
    fi
    if ! command -v sha256sum >/dev/null 2>&1; then
        echo "error: sha256sum is required for -v downloads" >&2
        exit 1
    fi
    candidate="$staging/$ASSET"
    sums="$staging/SHA256SUMS"

    auth_args=
    if [ -n "$token" ]; then
        auth_args="-H Authorization: Bearer $token"
    fi

    # shellcheck disable=SC2086  # auth_args is intentionally word-split (empty or one -H pair)
    if ! curl -fsSL --retry 3 $auth_args -o "$candidate" "$RELEASE_BASE/$version/$ASSET"; then
        echo "error: download failed: $RELEASE_BASE/$version/$ASSET (does the tag exist and ship $ASSET? set GH_TOKEN if rate-limited)" >&2
        exit 1
    fi
    if ! curl -fsSL --retry 3 $auth_args -o "$sums" "$RELEASE_BASE/$version/SHA256SUMS"; then
        echo "error: checksum download failed: $RELEASE_BASE/$version/SHA256SUMS" >&2
        exit 1
    fi

    # Verify the SHA-256 for this asset against the release's SHA256SUMS. sha256sum -c compares
    # case-insensitively, so the uppercase hashes Windows generated check cleanly. CR is
    # stripped in case the file was written with CRLF.
    expected=$(awk -v a="$ASSET" '{ sub(/\r$/, "") } $2 == a { print $1 }' "$sums")
    if [ -z "$expected" ]; then
        echo "error: SHA256SUMS does not list $ASSET" >&2
        exit 1
    fi
    if ! (cd "$staging" && printf '%s  %s\n' "$expected" "$ASSET" | sha256sum -c -); then
        echo "error: SHA-256 mismatch for $ASSET" >&2
        exit 1
    fi
fi

# --- verify identity: the artifact must report the version we asked for ---
chmod 0755 "$candidate"
report=$("$candidate" version) || {
    echo "error: candidate '$candidate' does not run" >&2
    exit 1
}
echo "artifact: $report"
if [ -n "$version" ]; then
    case "$report" in
        *"$version"*) ;;
        *)
            echo "error: artifact reports '$report', which does not carry version '$version'" >&2
            exit 1
            ;;
    esac
fi

# --- Hyper-V socket prerequisites ---
# The agent binds AF_VSOCK, which needs the hv_sock module and its /dev/vsock device. Persist the
# load so a reboot keeps the transport, load it now, and insist the device exists.
mkdir -p /etc/modules-load.d
if ! grep -qx 'hv_sock' /etc/modules-load.d/hv_sock.conf 2>/dev/null; then
    echo 'hv_sock' >> /etc/modules-load.d/hv_sock.conf
fi
if [ ! -e /dev/vsock ]; then
    modprobe hv_sock 2>/dev/null || true
fi
if [ ! -e /dev/vsock ]; then
    echo "error: /dev/vsock is absent even after loading hv_sock." >&2
    echo "  Is this a Hyper-V VM with a supported kernel? The agent needs the AF_VSOCK transport." >&2
    exit 1
fi

# --- install ---
install -d -m 0755 "$INSTALL_DIR"

# Stage the replacement and validate it in place BEFORE it replaces a working binary. A verified
# candidate that later fails to start is rolled back, so a working install is never lost.
install -m 0755 "$candidate" "$BIN.new"
if ! "$BIN.new" info >/dev/null; then
    echo "error: candidate failed 'hcsguest info'; the working binary (if any) was left alone" >&2
    rm -f "$BIN.new"
    exit 1
fi

if [ -e "$BIN" ]; then
    cp -p "$BIN" "$BACKUP"
fi
mv -f "$BIN.new" "$BIN"

# --- install the unit and start it ---
cat > "$UNIT" <<'EOF'
[Unit]
Description=hcsguest agent (Hyper-V socket)
Documentation=https://github.com/joshmakestuff/hcsctl/issues/40

# Not After=network.target: the agent answers over a Hyper-V socket, which needs no NIC, DHCP
# lease or firewall rule. It needs AF_VSOCK, loaded via /etc/modules-load.d/hv_sock.conf.
After=systemd-modules-load.service

# StartLimitIntervalSec belongs in [Unit], not [Service]. In [Service] systemd warns "Unknown
# key" and ignores it, so the crash loop below would give up silently.
StartLimitIntervalSec=0

[Service]
Type=simple
ExecStart=/opt/hcsguest/hcsguest serve
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable hcsguest.service
systemctl restart hcsguest.service

# A unit that stays active proves the vsock listener bound: if listen() failed, serve would exit
# and the unit would be crash-looping. Poll briefly, then assert.
i=0
while [ "$i" -lt 15 ]; do
    if [ "$(systemctl is-active hcsguest.service)" = "active" ]; then
        break
    fi
    sleep 1
    i=$((i + 1))
done
state=$(systemctl is-active hcsguest.service || true)
echo "hcsguest unit: $state"
if [ "$state" != "active" ]; then
    echo "hcsguest is not active; journal follows" >&2
    journalctl -u hcsguest.service --no-pager -n 40 >&2 || true
    rollback
    exit 1
fi

# Local check only: proves the binary runs and reads this guest's state. It does NOT prove the
# host can reach it -- that is a host-side check, for the same reason a listener inside a guest
# is not reachability.
"$BIN" info >/dev/null
echo "hcsguest info: ok"
