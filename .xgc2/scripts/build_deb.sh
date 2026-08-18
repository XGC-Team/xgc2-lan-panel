#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/../.." && pwd)"
package_distribution="${PACKAGE_DISTRIBUTION:-}"
output_dir="${XGC2_LAN_PANEL_DEB_OUTPUT_DIR:-${repo_root}/debs}"

if [[ -z "${package_distribution}" && -r /etc/os-release ]]; then
  # shellcheck disable=SC1091
  . /etc/os-release
  package_distribution="${VERSION_CODENAME:-${UBUNTU_CODENAME:-}}"
fi
case "${package_distribution}" in
  bionic|focal|jammy|noble) ;;
  *)
    echo "PACKAGE_DISTRIBUTION must be bionic, focal, jammy, or noble" >&2
    exit 1
    ;;
esac

package_base_version="$(
  awk -F': *' '/^version:/ {print $2; exit}' "${repo_root}/.xgc2/product.yml"
)"
if [[ -z "${package_base_version}" ]]; then
  echo "package version is missing" >&2
  exit 1
fi
version="${PACKAGE_VERSION:-${package_base_version}~${package_distribution}}"
case "${version}" in
  *"~${package_distribution}"*|*"+${package_distribution}"*) ;;
  *)
    echo "binary package version ${version} must identify ${package_distribution}" >&2
    exit 1
    ;;
esac

arch="$(dpkg --print-architecture)"
case "${arch}" in
  amd64) goarch=amd64 ;;
  arm64) goarch=arm64 ;;
  *)
    echo "unsupported Debian architecture ${arch}" >&2
    exit 1
    ;;
esac

mkdir -p "${repo_root}/.ci" "${output_dir}"
work_dir="$(mktemp -d "${repo_root}/.ci/package.XXXXXX")"
trap 'rm -rf -- "${work_dir}"' EXIT
binary="${work_dir}/xgc2-lan-panel"

GOOS=linux GOARCH="${goarch}" XGC2_LAN_PANEL_OUTPUT="${binary}" \
  "${repo_root}/.xgc2/scripts/build.sh"
test -x "${binary}"
test "$("${binary}" --version)" = "${package_base_version}"

pack_one() {
  local package_name="$1"
  local command_name="$2"
  local depends="$3"
  local recommends="$4"
  local description="$5"
  local extra_fn="${6:-}"
  local pkg_root="${work_dir}/pkg/${package_name}"

  install -d \
    "${pkg_root}/DEBIAN" \
    "${pkg_root}/usr/bin" \
    "${pkg_root}/usr/share/doc/${package_name}"
  install -m 0755 "${binary}" "${pkg_root}/usr/bin/${command_name}"
  install -m 0644 "${repo_root}/LICENSE" \
    "${pkg_root}/usr/share/doc/${package_name}/copyright"
  if [[ -n "${extra_fn}" ]]; then
    "${extra_fn}" "${pkg_root}"
  fi

  {
    echo "Package: ${package_name}"
    echo "Version: ${version}"
    echo "Section: net"
    echo "Priority: optional"
    echo "Architecture: ${arch}"
    echo "Maintainer: XGC Team"
    if [[ -n "${depends}" ]]; then
      echo "Depends: ${depends}"
    fi
    if [[ -n "${recommends}" ]]; then
      echo "Recommends: ${recommends}"
    fi
    echo "Description: ${description}"
  } >"${pkg_root}/DEBIAN/control"

  test -x "${pkg_root}/usr/bin/${command_name}"
  test "$("${pkg_root}/usr/bin/${command_name}" --version)" = "${package_base_version}"

  local artifact="${output_dir}/${package_name}_${version}_${arch}.deb"
  rm -f -- "${artifact}"
  fakeroot dpkg-deb --build "${pkg_root}" "${artifact}" >/dev/null
  dpkg-deb -I "${artifact}"
  echo "Debian artifact written to ${artifact}"
}

install_beacon_unit() {
  local pkg_root="$1"
  install -d "${pkg_root}/lib/systemd/system"
  install -m 0644 \
    "${repo_root}/packaging/systemd/xgc2-lan-beacon.service" \
    "${pkg_root}/lib/systemd/system/xgc2-lan-beacon.service"
  cat >"${pkg_root}/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
if [ "$1" = configure ]; then
  if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload >/dev/null 2>&1 || true
    systemctl enable xgc2-lan-beacon.service >/dev/null 2>&1 || true
  fi
fi
EOF
  cat >"${pkg_root}/DEBIAN/prerm" <<'EOF'
#!/bin/sh
set -e
if [ "$1" = remove ] && command -v systemctl >/dev/null 2>&1; then
  systemctl disable --now xgc2-lan-beacon.service >/dev/null 2>&1 || true
fi
EOF
  chmod 0755 "${pkg_root}/DEBIAN/postinst" "${pkg_root}/DEBIAN/prerm"
}

pack_one \
  xgc2-lan-probe \
  xgc2-lan-probe \
  "" \
  "" \
  "XGC2 LAN Panel operator probe (discover robots on the LAN)"
pack_one \
  xgc2-lan-beacon \
  xgc2-lan-beacon \
  "" \
  "network-manager" \
  "XGC2 LAN Panel robot beacon (be discovered; apply NIC / Wi-Fi)" \
  install_beacon_unit
