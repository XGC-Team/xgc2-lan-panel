#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

bash -n .xgc2/scripts/*.sh
export PYTHONPYCACHEPREFIX="${PYTHONPYCACHEPREFIX:-/tmp/xgc2-lan-panel-pycache}"
python3 -m py_compile .xgc2/scripts/xgc2_artifact_manifest.py

if grep -ERn \
  'xgc2\.build-artifact\.v2|actions/(checkout|setup-node|setup-go|upload-artifact)@v[0-9]' \
  .github/workflows .xgc2/scripts/xgc2_artifact_manifest.py; then
  echo "release contract contains a legacy schema or floating action" >&2
  exit 1
fi
grep -q 'xgc2.build-artifact.v1' .xgc2/scripts/xgc2_artifact_manifest.py
if grep -ERn -- '--(prepare-action|dependency-set-digest|dependency-mode)' \
  .github/workflows .xgc2/scripts/xgc2_artifact_manifest.py; then
  echo "build manifest generation must not embed release dependency inputs" >&2
  exit 1
fi
grep -q '^      prepare_action:' .github/workflows/release.yml
grep -q '^      dependency_set_digest:' .github/workflows/release.yml
if [[ "$(grep -c 'verify-build' .github/workflows/ci.yml)" -ne 1 ||
      "$(grep -c 'verify-build' .github/workflows/release.yml)" -ne 1 ]]; then
  echo "CI and release must verify each build manifest before upload" >&2
  exit 1
fi

required_files=(
  .github/workflows/ci.yml
  .github/workflows/release.yml
  .github/workflows/ci-bootstrap-gate.yml
  .xgc2/product.yml
  .xgc2/scripts/build.sh
  .xgc2/scripts/build_deb.sh
  .xgc2/scripts/check_package_compliance.sh
  .xgc2/scripts/smoke_test_installed.sh
  .xgc2/scripts/xgc2_artifact_manifest.py
  LICENSE
  README.md
  cmd/xgc2-lan-panel/main.go
  go.mod
  go.sum
  packaging/systemd/xgc2-lan-beacon.service
)
for file in "${required_files[@]}"; do
  if [[ ! -f "${file}" ]]; then
    echo "Missing required file: ${file}" >&2
    exit 1
  fi
done

unformatted="$(gofmt -l cmd internal)"
if [[ -n "${unformatted}" ]]; then
  echo "Go sources are not formatted:" >&2
  echo "${unformatted}" >&2
  exit 1
fi
go mod verify

if grep -ERn -- 'aliyun|aliyuncs|registry\.cn-|xgc2\.apt\.xiaokang' \
  --exclude-dir=node_modules --exclude-dir=.git --exclude-dir=web/dist \
  --exclude='*.md' .; then
  echo "committed product files must not name private APT or CN mirrors" >&2
  exit 1
fi

echo "xgc2-lan-panel package compliance passed."
