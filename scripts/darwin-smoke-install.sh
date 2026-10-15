#!/usr/bin/env bash
# First-run service installation on a disposable GitHub-hosted runner only.
# Includes a real TUN/DNS protection cycle on this disposable runner.
set -euo pipefail
if [[ "$(uname -s)" != Darwin || "${GITHUB_ACTIONS:-}" != true || "${RUNNER_ENVIRONMENT:-}" != github-hosted ]]; then
  echo "Requires a disposable GitHub-hosted macOS runner" >&2
  exit 1
fi
APP="${1:?usage: darwin-smoke-install.sh <app>}"
CORE="$APP/Contents/MacOS/offveil-core"
INSTALLED="/Library/Application Support/offveil/offveil-core"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/offveil-upgrade.XXXXXX")"
cleanup() {
  local result=$?
  if [[ "$result" != 0 ]]; then
    sudo tail -n 120 '/Library/Application Support/offveil/logs/offveil-core.err.log' || true
    "$CORE" support --output "${GITHUB_WORKSPACE}/dist-mac-ci/failure-support.zip" || true
  fi
  sudo "$CORE" stop || true
  sudo "$CORE" uninstall || true
  rm -rf "$WORK"
}
trap cleanup EXIT

# Support collection must work before a daemon has ever been installed.
"$CORE" support --output "$WORK/offline-support.zip" > "$WORK/offline-support.json"
[[ -s "$WORK/offline-support.zip" ]]
# A user accidentally executing just the binary must not create a stray daemon.
if "$CORE" > "$WORK/no-arguments.txt" 2>&1; then
  echo "Unprivileged no-argument core unexpectedly started" >&2
  exit 1
fi

sudo "$CORE" setup
# Hosted runners already allow broad passwordless sudo. Check our own policy
# independently so that a missing/invalid offveil sudoers file cannot be masked.
sudo /usr/sbin/visudo -cf /etc/sudoers.d/offveil
for name in offveil-core sing-box ciadpi; do
  dst="$(dirname "$INSTALLED")/$name"
  cmp "$APP/Contents/MacOS/$name" "$dst"
  codesign --verify --strict "$dst"
done

ping_until_ready() {
  local i
  for i in {1..50}; do
    if "$INSTALLED" client -method ping; then return 0; fi
    sleep 0.2
  done
  echo "LaunchDaemon socket not reachable by UI user" >&2
  return 1
}
ping_until_ready
# The daemon creates this archive as root. Verify that the desktop user can
# read the completed ZIP, rather than just receiving a successful IPC response.
"$INSTALLED" client -method diagnostics > "$WORK/diagnostics-response.json"
node - "$WORK/diagnostics-response.json" <<'NODE'
const fs = require('node:fs');
const reply = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
const path = reply.result?.path;
if (!reply.ok || typeof path !== 'string' ||
    !path.startsWith('/Library/Application Support/offveil/diagnostics/')) {
  throw new Error('Invalid diagnostics response');
}
const zip = fs.readFileSync(path);
if (zip.length < 4 || zip.readUInt32LE(0) !== 0x04034b50) {
  throw new Error('Diagnostics archive is not a readable ZIP');
}
console.log('Diagnostics ZIP is readable by the desktop user.');
NODE

dns_snapshot() {
  local service
  /usr/sbin/networksetup -listallnetworkservices | tail -n +2 | while IFS= read -r service; do
    [[ -n "$service" && "$service" != \** ]] || continue
    printf '%s\n' "$service"
    /usr/sbin/networksetup -getdnsservers "$service"
  done
}
dns_snapshot > "$WORK/dns-before.txt"
TEST_URL=""
for candidate in https://github.com https://www.microsoft.com https://example.com; do
  if /usr/bin/curl -4 --fail --silent --show-error --connect-timeout 6 --max-time 15 "$candidate" -o /dev/null; then
    TEST_URL="$candidate"
    break
  fi
done
[[ -n "$TEST_URL" ]] || { echo "No working HTTPS control endpoint before protection" >&2; exit 1; }
echo "Baseline HTTPS passed: $TEST_URL"
if ! "$INSTALLED" client -method start -timeout 120s > "$WORK/protection-start.json"; then
  sudo tail -n 100 '/Library/Application Support/offveil/logs/offveil-core.err.log' || true
  exit 1
fi
node - "$WORK/protection-start.json" <<'NODE'
const fs = require('node:fs');
const reply = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
const s = reply.result;
if (!reply.ok || !s?.protection || s.state !== 'active' ||
    !s.tunnel?.up || !s.desync?.up || !s.dns?.stub_up) {
  throw new Error(`Real protection failed: ${JSON.stringify(reply)}`);
}
console.log('Real protection reports active with TUN, DNS and ByeDPI up.');
NODE
/sbin/route -n get 104.18.26.120 > "$WORK/protected-route.txt"
grep -Eq 'interface: utun[0-9]+' "$WORK/protected-route.txt"
/usr/bin/curl -4 --socks5 127.0.0.1:18080 --fail --silent --show-error --connect-timeout 6 --max-time 20 "$TEST_URL" -o /dev/null
echo "HTTPS through ByeDPI SOCKS passed."
/usr/bin/curl -4 --socks5 127.0.0.1:18081 --fail --silent --show-error --connect-timeout 6 --max-time 20 "$TEST_URL" -o /dev/null
echo "HTTPS through sing-box SOCKS passed."
/usr/bin/curl -4 --fail --silent --show-error --connect-timeout 6 --max-time 20 "$TEST_URL" -o /dev/null
echo "HTTPS through the active TUN passed."
"$INSTALLED" client -method stop -timeout 45s
dns_snapshot > "$WORK/dns-after.txt"
cmp "$WORK/dns-before.txt" "$WORK/dns-after.txt"
echo "Real TUN startup, routed HTTPS, ByeDPI SOCKS HTTPS and DNS restoration passed."

"$INSTALLED" client -method shutdown
for i in {1..50}; do
  [[ -S /var/run/offveil/core.sock ]] || break
  sleep 0.2
done
if [[ -S /var/run/offveil/core.sock ]]; then
  echo "LaunchDaemon did not release its socket after shutdown" >&2
  exit 1
fi
# Exercise the UI's demand-start route after the initial admin installation.
/usr/bin/sudo -n "$INSTALLED" start
ping_until_ready

# A stopped UI indicator must not prevent updating a hung daemon. Suspend the
# real job so IPC cannot answer, then exercise the passwordless launchd stop.
DAEMON_PID="$(sudo /bin/launchctl print system/offveil-core | awk '/^[[:space:]]*pid = / { print $3; exit }')"
[[ "$DAEMON_PID" =~ ^[0-9]+$ ]]
sudo /bin/kill -STOP "$DAEMON_PID"
/usr/bin/sudo -n "$INSTALLED" stop
for i in {1..50}; do
  [[ -S /var/run/offveil/core.sock ]] || break
  sleep 0.1
done
if "$INSTALLED" client -method ping -timeout 1s; then
  echo "Suspended daemon remained reachable after managed stop" >&2
  exit 1
fi
/usr/bin/sudo -n "$INSTALLED" start
ping_until_ready
echo "Managed stop and restart of an unresponsive daemon passed."

# Exercise refresh of an existing installation with a valid, different payload.
# Re-sign only a temporary sidecar to model an older build without corrupting it.
for name in offveil-core sing-box ciadpi; do
  cp "$APP/Contents/MacOS/$name" "$WORK/$name"
done
codesign --force --sign - --timestamp=none --identifier com.offveil.smoke.previous "$WORK/ciadpi"
"$INSTALLED" client -method shutdown
sleep 1
sudo "$WORK/offveil-core" setup
ping_until_ready
cmp "$WORK/ciadpi" "$(dirname "$INSTALLED")/ciadpi"
"$INSTALLED" client -method shutdown
sleep 1
sudo "$CORE" setup
ping_until_ready
for name in offveil-core sing-box ciadpi; do
  cmp "$APP/Contents/MacOS/$name" "$(dirname "$INSTALLED")/$name"
done
echo "First install, signature preservation, non-root IPC, demand-start and payload refresh passed."
