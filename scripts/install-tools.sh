#!/bin/bash
set -euo pipefail

# Tools installation recipes
#
# These are fragile, non-portable, and often require root
#
NFPM_VERSION=0.9.3
#from https://github.com/goreleaser/nfpm/releases/download/v0.9.3/nfpm_0.9.3_checksums.txt
NFPM_SHA256=f875ac060a30ec5c164e5444a7278322b276707493fa0ced6bfdd56640f0a6ea

plaform=$(go env GOHOSTOS)

install-nfpm() {
  if [[ platform != "linux" ]]; then
    echo "nfpm not supported on platform ${platform}"
    return 1
  fi
  curl -Ls https://github.com/goreleaser/nfpm/releases/download/v${NFPM_VERSION}/nfpm_${NFPM_VERSION}_Linux_x86_64.tar.gz > nfpm.tar.gz
  echo "${NFPM_SHA256} nfpm.tar.gz" | sha256sum -c
  tar xzvf nfpm.tar.gz
  mv nfpm /usr/local/bin
}

install-rpmbuild() {
  case "${platform}" in 
    "linux" )
      # assume debian
      apt update -q && apt install rpm -yq
      ;;
    "darwin" )
      brew install rpm
      ;;
    *)
      echo "rpmbuild not supported on platform ${platform}"
      return 1
  esac
}

install-sha256sum-darwin() {
  if [[ platform = "darwin" ]]; then
    brew install coreutils && ln -s $(which gsha256sum) /usr/local/bin/sha256sum
  fi
}

install-github-release() {
	GO111MODULE=off go get -u github.com/aktau/github-release
}

install-package_cloud() {
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
