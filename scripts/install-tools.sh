#!/bin/bash
set -euo pipefail

# Tools installation recipes
#
# These are fragile, non-portable, and often require root
#
NFPM_VERSION=0.9.3
#from https://github.com/goreleaser/nfpm/releases/download/v0.9.3/nfpm_0.9.3_checksums.txt
NFPM_SHA256_LINUX=f875ac060a30ec5c164e5444a7278322b276707493fa0ced6bfdd56640f0a6ea
NFPM_SHA256_DARWIN=1b8c96807c6acaa8f76f1e8c8568e49a9cc860e4f282efb3923fb672407c9a00

platform=$(go env GOHOSTOS)

install-nfpm() {
  if which nfpm; then
    echo "nfpm already installed"
    return 0
  fi

  local tarball sha256sum
  case "${platform}" in
    "linux" )
      tarball=nfpm_${NFPM_VERSION}_Linux_x86_64.tar.gz 
      sha256sum="${NFPM_SHA256_LINUX}"
      ;;
    "darwin" )
      tarball=nfpm_${NFPM_VERSION}_Darwin_x86_64.tar.gz 
      sha256sum="${NFPM_SHA256_DARWIN}"
      ;;
    * )
      echo "nfpm not supported on platform ${platform}"
      return 1
  esac

  if which nfpm; then
    echo "nfpm already installed"
    return 0
  fi

	local tmpdir
	tmpdir=$(mktemp -d 2>/dev/null || mktemp -d -t 'nfpm')
  pushd "${tmpdir}"
  curl -Ls https://github.com/goreleaser/nfpm/releases/download/v${NFPM_VERSION}/${tarball} > nfpm.tar.gz
  echo "${sha256sum} nfpm.tar.gz" | sha256sum -c
  tar xzvf nfpm.tar.gz
  mv nfpm /usr/local/bin
  popd "${tmpdir}"
  rm -rf "${tmpdir}"
}

install-rpmbuild() {
  if which rpmbuild; then
    echo "rpmbuild already installed"
    return 0
  fi
  case "${platform}" in 
    "linux" )
      # assume debian
      apt update -q && apt install rpm -yq
      ;;
    "darwin" )
      brew install -f rpm
      ;;
    *)
      echo "rpmbuild not supported on platform ${platform}"
      return 1
  esac
}

install-sha256sum() {
  if which sha256sum; then
    echo "sha256sum already installed"
    return 0
  fi
  if [[ platform = "darwin" ]]; then
    brew install -f coreutils && ln -s $(which gsha256sum) /usr/local/bin/sha256sum
  fi
}

install-github-release() {
  if which github-release; then
    echo "github-release already installed"
    return 0
  fi
	GO111MODULE=off go get -u github.com/aktau/github-release
}

install-package_cloud() {
  if which package_cloud; then
    echo "github-release already installed"
    return 0
  fi
	gem install package_cloud
}

install-all() {
  install-nfpm
  install-rpmbuild
  install-sha256sum
  install-github-release
  install-package_cloud
}

# this guard makes it possible to source this script, or execute it directly
if [[ $0 = "$BASH_SOURCE" ]]; then
  for t in ${@}; do
    install-$t
  done
fi
