#!/usr/bin/env bash
set -euo pipefail

dpkg -s xgc2-lan-probe >/dev/null
dpkg -s xgc2-lan-beacon >/dev/null
test -x /usr/bin/xgc2-lan-probe
test -x /usr/bin/xgc2-lan-beacon
test -f /lib/systemd/system/xgc2-lan-beacon.service
grep -q '/usr/bin/xgc2-lan-beacon' /lib/systemd/system/xgc2-lan-beacon.service

probe_version="$(xgc2-lan-probe --version)"
beacon_version="$(xgc2-lan-beacon --version)"
case "${probe_version}" in
  dev|"")
    echo "installed probe has invalid version ${probe_version}" >&2
    exit 1
    ;;
esac
test "${probe_version}" = "${beacon_version}"

xgc2-lan-beacon --once | grep -q '"kind": "xgc2-lan-beacon"'

file /usr/bin/xgc2-lan-probe | tee /tmp/xgc2-lan-probe-file.txt
file /usr/bin/xgc2-lan-beacon | tee /tmp/xgc2-lan-beacon-file.txt

echo "xgc2-lan-panel installed smoke test passed (version ${probe_version})."
