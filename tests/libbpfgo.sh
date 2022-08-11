#!/bin/bash

#
# This test is executed by github workflows inside the action runners
#

info() {
    echo -n "INFO: "
    echo $@
}

error_exit() {
    echo -n "ERROR: "
    echo $@
    exit 1
}

TRACEE_DIR="$(realpath ./)"
TEST_DIR="$(dirname $(realpath "${0}"))"
LIBBPFGO_DIR="${TEST_DIR}/libbpfgo"
LIBBPFGO_REPO="https://github.com/aquasecurity/libbpfgo.git"

if [[ -d "${LIBBPFGO_DIR}" ]]
then
    info "Reusing ${LIBBPFGO_DIR}"
else
    git clone "${LIBBPFGO_REPO}" "${LIBBPFGO_DIR}" || error_exit "could not clone ${LIBBPFGO_REPO}"
fi

echo "replace github.com/aquasecurity/libbpfgo => ${LIBBPFGO_DIR}" >> "${TRACEE_DIR}"/go.mod

set -e
make -C "${TRACEE_DIR}"
set +e

rm -rf "${LIBBPFGO_DIR}"

info "SUCCESS"

exit 0
