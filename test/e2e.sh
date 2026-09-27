#!/usr/bin/env bash
set -euo pipefail

engine=${CONTAINER_ENGINE:-docker}
key_type=${KEY_TYPE:-rsa}
port=${PORT:-8765}
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
work=$(mktemp -d)
default_images=(
  docker.io/library/debian:11 docker.io/library/debian:12 docker.io/library/debian:13 docker.io/library/debian:testing
  docker.io/library/ubuntu:20.04 docker.io/library/ubuntu:22.04 docker.io/library/ubuntu:24.04 docker.io/library/ubuntu:26.04
  docker.io/library/fedora:42 docker.io/library/fedora:43 docker.io/library/fedora:44 docker.io/library/fedora:rawhide
  quay.io/centos/centos:stream10 docker.io/rockylinux/rockylinux:10 docker.io/library/almalinux:10
  docker.io/opensuse/leap:16.0 docker.io/opensuse/tumbleweed registry.suse.com/bci/bci-base:16.0
)
rsa_only_images=(
  quay.io/centos/centos:stream9
  docker.io/rockylinux/rockylinux:8 docker.io/rockylinux/rockylinux:9
  docker.io/library/almalinux:8 docker.io/library/almalinux:9
  docker.io/library/oraclelinux:8 docker.io/library/oraclelinux:9
  docker.io/library/amazonlinux:2 docker.io/library/amazonlinux:2023 docker.io/library/centos:7
  docker.io/opensuse/leap:15.6 registry.suse.com/bci/bci-base:15.7
)
[[ $key_type == rsa ]] && default_images+=("${rsa_only_images[@]}")
read -r -a images <<<"${IMAGES:-${default_images[*]}}"
containers=()
server=""

cleanup() {
  [[ -n "$server" ]] && kill "$server" 2>/dev/null || true
  for c in "${containers[@]}"; do
    $engine rm -f "$c" >/dev/null 2>&1 || true
  done
  rm -rf "$work"
}
trap cleanup EXIT

CGO_ENABLED=0 go -C "$root" build -o "$work/bin/pkgrepo" ./cmd/pkgrepo

$engine build --network host -q -t pkgrepo-e2e-builder - >/dev/null <<'EOF'
FROM docker.io/library/fedora:44
RUN dnf install -y --setopt=install_weak_deps=False rpm-sign rpm-build createrepo_c dpkg openssl && dnf clean all
EOF

cat >"$work/config.json" <<EOF
{
  "url": "http://127.0.0.1:$port",
  "name": "octelium",
  "title": "Octelium",
  "uid": "Octelium Packages <packages@example.com>",
  "retain": 1,
  "grace": "72h",
  "formats": {"deb": {}, "rpm": {}}
}
EOF

cat >"$work/build.sh" <<'EOF'
set -euo pipefail
export HOME=/tmp
version=$1
out=/work/v$version
mkdir -p "$out"
if [[ ! -f /work/key.pem ]]; then
  case $KEY_TYPE in
    rsa) openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out /work/key.pem ;;
    ecdsa) openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out /work/key.pem ;;
    *) echo "unsupported KEY_TYPE $KEY_TYPE" >&2; exit 1 ;;
  esac
fi

deb() {
  local name=$1 arch=$2 dir
  dir=$(mktemp -d)
  mkdir -p "$dir/DEBIAN" "$dir/usr/bin" "$dir/usr/share/$name"
  if [[ $arch == all ]]; then
    echo "$version" >"$dir/usr/share/$name/version"
  else
    printf '#!/bin/sh\necho %s\n' "$version" >"$dir/usr/bin/$name"
    chmod 0755 "$dir/usr/bin/$name"
  fi
  cat >"$dir/DEBIAN/control" <<CONTROL
Package: $name
Version: $version-1
Architecture: $arch
Maintainer: Octelium <packages@example.com>
Description: Octelium repository test package
 Used by the end-to-end tests.
CONTROL
  dpkg-deb -Zxz --root-owner-group --build "$dir" "$out/${name}_$version-1_$arch.deb" >/dev/null
}

rpm() {
  local name=$1 arch=$2 top
  top=$(mktemp -d)
  mkdir -p "$top/SPECS"
  cat >"$top/SPECS/$name.spec" <<SPEC
%global debug_package %{nil}
Name: $name
Version: $version
Release: 1
Summary: Octelium repository test package
License: Apache-2.0
$([[ $arch == noarch ]] && echo "BuildArch: noarch")

%description
Used by the end-to-end tests.

%install
mkdir -p %{buildroot}/usr/bin %{buildroot}/usr/share/$name
echo $version > %{buildroot}/usr/share/$name/version
printf '#!/bin/sh\necho %s\n' $version > %{buildroot}/usr/bin/$name-$arch
chmod 0755 %{buildroot}/usr/bin/$name-$arch

%files
/usr/share/$name/version
/usr/bin/$name-$arch
SPEC
  rpmbuild -bb --quiet --target "$arch" \
    --define "_topdir $top" \
    --define "_binary_payload w9.gzdio" \
    --define "_build_id_links none" \
    "$top/SPECS/$name.spec"
  find "$top/RPMS" -name '*.rpm' -exec cp {} "$out/" \;
}

for arch in amd64 arm64; do deb octelium-e2e "$arch"; done
deb octelium-e2e-data all
for arch in x86_64 aarch64; do rpm octelium-e2e "$arch"; done
rpm octelium-e2e-data noarch

/work/bin/pkgrepo publish --config /work/config.json --storage file:///work/repo --key file:/work/key.pem "$out"
EOF

cat >"$work/client.sh" <<EOF
set -eu
action=\$1
version=\$2
base=http://127.0.0.1:$port
EOF
cat >>"$work/client.sh" <<'EOF'
if command -v apt-get >/dev/null; then
  export DEBIAN_FRONTEND=noninteractive
  if [ "$action" = install ]; then
    rm -f /etc/apt/sources.list /etc/apt/sources.list.d/*
    install -d -m 0755 /etc/apt/keyrings
    cp /repo/keys/octelium.gpg /etc/apt/keyrings/octelium.gpg
    cp /repo/deb/octelium.sources /etc/apt/sources.list.d/octelium.sources
  fi
  apt-get update >/tmp/update.log 2>&1 || { cat /tmp/update.log; exit 1; }
  if grep -E '^(W|E|Err):' /tmp/update.log; then exit 1; fi
  apt-get install -y octelium-e2e octelium-e2e-data >/dev/null
  test "$(octelium-e2e)" = "$version"
elif command -v zypper >/dev/null; then
  z="zypper --non-interactive --gpg-auto-import-keys"
  if [ "$action" = install ]; then
    rm -f /etc/zypp/repos.d/*.repo
    $z addrepo "$base/rpm/octelium.repo"
    $z install octelium-e2e octelium-e2e-data
  else
    $z refresh
    $z update octelium-e2e octelium-e2e-data
  fi
  test "$(octelium-e2e-x86_64)" = "$version"
else
  pm=yum
  command -v dnf >/dev/null && pm=dnf
  if [ "$action" = install ]; then
    cp /repo/rpm/octelium.repo /etc/yum.repos.d/octelium.repo
    $pm -y --disablerepo='*' --enablerepo=octelium install octelium-e2e octelium-e2e-data
  else
    $pm clean expire-cache
    $pm -y --disablerepo='*' --enablerepo=octelium upgrade octelium-e2e octelium-e2e-data
  fi
  rpm -q gpg-pubkey
  test "$(octelium-e2e-x86_64)" = "$version"
fi
test "$(cat /usr/share/octelium-e2e-data/version)" = "$version"
echo "$action $version ok"
EOF

run_builder() {
  $engine run --rm --network host --user "$(id -u):$(id -g)" -e KEY_TYPE="$key_type" -v "$work:/work" pkgrepo-e2e-builder bash /work/build.sh "$1"
}

run_builder 1.0.0

python3 -m http.server "$port" --bind 127.0.0.1 --directory "$work/repo" >"$work/http.log" 2>&1 &
server=$!
for _ in $(seq 50); do
  curl -fs "http://127.0.0.1:$port/manifest.json" >/dev/null && break
  sleep 0.2
done

for image in "${images[@]}"; do
  name=pkgrepo-e2e-$(echo "$image" | tr -c 'a-zA-Z0-9\n' '-')
  $engine rm -f "$name" >/dev/null 2>&1 || true
  containers+=("$name")
  $engine run -d --name "$name" --network host -v "$work/repo:/repo:ro" -v "$work/client.sh:/client.sh:ro" "$image" sleep infinity >/dev/null
done

phase() {
  local action=$1 version=$2 failed=()
  local pids=()
  for c in "${containers[@]}"; do
    $engine exec "$c" sh /client.sh "$action" "$version" >"$work/$c.$action.log" 2>&1 &
    pids+=($!)
  done
  for i in "${!pids[@]}"; do
    if wait "${pids[$i]}"; then
      echo "PASS $action ${images[$i]}"
    else
      echo "FAIL $action ${images[$i]}"
      sed 's/^/    /' "$work/${containers[$i]}.$action.log" | tail -30
      failed+=("${images[$i]}")
    fi
  done
  [[ ${#failed[@]} -eq 0 ]]
}

status=0
phase install 1.0.0 || status=1
run_builder 1.1.0
phase upgrade 1.1.0 || status=1

if grep -q 'InRelease' "$work/http.log" && ! grep -q 'by-hash/SHA256' "$work/http.log"; then
  echo "FAIL apt did not use by-hash indices"
  status=1
fi
if grep -q 'repomd.xml ' "$work/http.log" && ! grep -q 'repomd.xml.asc' "$work/http.log"; then
  echo "FAIL repository metadata signature was not fetched"
  status=1
fi
grep -q '"retired"' "$work/repo/manifest.json" || { echo "FAIL old packages were not retired"; status=1; }
exit $status
