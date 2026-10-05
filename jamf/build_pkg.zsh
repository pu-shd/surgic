#!/bin/zsh
# Build a Jamf-deployable package containing the pf airgap ruleset and the
# sudoers allowlist, both generated from the site config.
#
#   jamf/build_pkg.zsh config/surgic.toml [version]
#
# Payload (root:wheel):
#   /etc/pf.anchors/airgap.rules  0644   (set network.pf_rules_managed = true)
#   /etc/sudoers.d/surgic         0440   (validated with visudo in postinstall)
set -euo pipefail
cd "${0:A:h}/.."
CONFIG="${1:?usage: $0 <config.toml> [version]}"
VERSION="${2:-$(date +%Y.%m.%d)}"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

mkdir -p "$WORK/root/etc/pf.anchors" "$WORK/root/etc/sudoers.d" "$WORK/scripts"
.venv/bin/surgic jamf pf-rules -c "$CONFIG" > "$WORK/root/etc/pf.anchors/airgap.rules"
.venv/bin/surgic jamf sudoers  -c "$CONFIG" > "$WORK/root/etc/sudoers.d/surgic"
/usr/sbin/visudo -cf "$WORK/root/etc/sudoers.d/surgic"
chmod 0644 "$WORK/root/etc/pf.anchors/airgap.rules"
chmod 0440 "$WORK/root/etc/sudoers.d/surgic"

cat > "$WORK/scripts/postinstall" <<'POST'
#!/bin/zsh
set -e
chown root:wheel /etc/pf.anchors/airgap.rules /etc/sudoers.d/surgic
chmod 0644 /etc/pf.anchors/airgap.rules
chmod 0440 /etc/sudoers.d/surgic
if ! /usr/sbin/visudo -cf /etc/sudoers.d/surgic; then
  rm -f /etc/sudoers.d/surgic   # never leave an unparseable sudoers file
  exit 1
fi
POST
chmod 0755 "$WORK/scripts/postinstall"

mkdir -p dist
/usr/bin/pkgbuild --root "$WORK/root" --scripts "$WORK/scripts" \
  --identifier org.example.surgic.host-controls --version "$VERSION" \
  --ownership recommended "dist/surgic-host-controls-${VERSION}.pkg"
print "Built dist/surgic-host-controls-${VERSION}.pkg (sign with productsign before upload to Jamf)."
