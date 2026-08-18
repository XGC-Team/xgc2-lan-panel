#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/../.." && pwd)"
cd "${repo_root}"

package_base_version="$(
  awk -F': *' '/^version:/ {print $2; exit}' "${repo_root}/.xgc2/product.yml"
)"
if [[ -z "${package_base_version}" ]]; then
  echo "package version is missing" >&2
  exit 1
fi

embed_ui() {
  mkdir -p "${repo_root}/cmd/xgc2-lan-panel/ui"
  if [[ -d "${repo_root}/web" ]]; then
    if [[ ! -d "${repo_root}/web/node_modules" ]]; then
      (cd "${repo_root}/web" && npm ci)
    fi
    (cd "${repo_root}/web" && npm run build)
    rm -rf "${repo_root}/cmd/xgc2-lan-panel/ui"
    mkdir -p "${repo_root}/cmd/xgc2-lan-panel/ui"
    cp -a "${repo_root}/web/dist/." "${repo_root}/cmd/xgc2-lan-panel/ui/"
  fi
}

node_major="0"
if command -v node >/dev/null 2>&1; then
  node_major="$(node -v | sed 's/^v//' | cut -d. -f1)"
fi
if [[ "${SKIP_UI_BUILD:-}" != "1" && "${node_major}" -ge 18 ]]; then
  embed_ui
elif [[ ! -f "${repo_root}/cmd/xgc2-lan-panel/ui/index.html" ]]; then
  echo "embedded UI missing and Node is too old to build it" >&2
  exit 1
fi

export CGO_ENABLED="${CGO_ENABLED:-0}"
export GOOS="${GOOS:-linux}"
export GOARCH="${GOARCH:-$(go env GOARCH)}"
mkdir -p "${repo_root}/bin"
outfile="${XGC2_LAN_PANEL_OUTPUT:-${repo_root}/bin/xgc2-lan-panel-linux-${GOARCH}}"
go build -trimpath -ldflags "-s -w -X main.version=${package_base_version}" \
  -o "${outfile}" ./cmd/xgc2-lan-panel
echo "built ${outfile}"
