#!/bin/bash
# Generate cloud-init configuration from templates
# This script creates customized cloud-init files for VM provisioning

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Default values
DISTRO=""
VERSION=""
KERNEL_FLAVOR=""
KERNEL_VERSION=""
ARCH=""
ENVIRONMENT=""

# Usage function
usage() {
    cat << EOF
Usage: $(basename "$0") [OPTIONS]

Generate cloud-init configuration files and ISO for VM provisioning.

OPTIONS:
    -d, --distro DISTRO              Distribution name (ubuntu, centos, alpine)
    -v, --distro-version VERSION     Distribution version (22.04, 24.04, 9, etc.)
    -f, --kernel-flavor FLAVOR       Kernel flavor (generic, aws, gcp, azure, mainline, vanilla, lts)
    -k, --kernel-version VERSION     Kernel version (5.19.0-50, 6.11.0-29, etc.)
    -a, --arch ARCH                  Architecture (x86_64, aarch64)
    -e, --env ENVIRONMENT            Environment type (local, aws)
    -h, --help                       Show this help message

EXAMPLES:
    # Ubuntu 22.04 with generic kernel for local development
    $(basename "$0") -d ubuntu -v 22.04 -f generic -k 5.19.0-50 -a x86_64 -e local

    # Ubuntu 24.04 with AWS kernel for CI/CD
    $(basename "$0") --distro ubuntu --distro-version 24.04 --kernel-flavor aws \\
        --kernel-version 6.11.0-29 --arch x86_64 --env aws

    # CentOS Stream 9 for local development
    $(basename "$0") -d centos -v 9 -f generic -k 5.14.0-503 -a x86_64 -e local

    # Alpine 3.19 with vanilla kernel
    $(basename "$0") -d alpine -v 3.19 -f vanilla -k 6.6.0 -a x86_64 -e local

SUPPORTED DISTRIBUTIONS:
    ubuntu          Ubuntu/Debian (uses apt-get)
    centos          CentOS/RHEL/Rocky/AlmaLinux (uses dnf/yum)
    alpine          Alpine Linux (uses apk)

KERNEL FLAVORS BY DISTRO:
    Ubuntu/Debian:  generic, aws, gcp, azure, mainline
    CentOS/RHEL:    generic, standard, mainline, elrepo
    Alpine:         vanilla, lts

ENVIRONMENTS:
    local           Local development (includes mount points for shared directories)
    aws             AWS/CI/CD (optimized for GitHub Actions, no local mounts)

OUTPUT:
    Generated files are placed in: ${SCRIPT_DIR}/generated/
    - {image-name}-user-data.yaml    Cloud-init user data configuration
    - {image-name}-meta-data.yaml    Cloud-init metadata
    
    Next steps:
    1. cd ${SCRIPT_DIR}/generated/
    2. cloud-localds {image-name}-cloud-init.iso {image-name}-user-data.yaml {image-name}-meta-data.yaml
    3. Copy ISO to your VM directory
    4. Boot VM with the cloud-init ISO

NAMING CONVENTION:
    Generated files follow: {distro}-{version}-{flavor}-{kernel-version}-{arch}
    Example: ubuntu-22.04-generic-5.19.0-50-x86_64

EOF
    exit 0
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -d|--distro)
            DISTRO="$2"
            shift 2
            ;;
        -v|--distro-version)
            VERSION="$2"
            shift 2
            ;;
        -f|--kernel-flavor)
            KERNEL_FLAVOR="$2"
            shift 2
            ;;
        -k|--kernel-version)
            KERNEL_VERSION="$2"
            shift 2
            ;;
        -a|--arch)
            ARCH="$2"
            shift 2
            ;;
        -e|--env)
            ENVIRONMENT="$2"
            shift 2
            ;;
        -h|--help)
            usage
            ;;
        *)
            echo "Error: Unknown option: $1" >&2
            echo "Use --help for usage information" >&2
            exit 1
            ;;
    esac
done

# Validate required arguments
if [[ -z "$DISTRO" ]]; then
    echo "Error: --distro is required" >&2
    echo "Use --help for usage information" >&2
    exit 1
fi

if [[ -z "$VERSION" ]]; then
    echo "Error: --distro-version is required" >&2
    echo "Use --help for usage information" >&2
    exit 1
fi

if [[ -z "$KERNEL_FLAVOR" ]]; then
    echo "Error: --kernel-flavor is required" >&2
    echo "Use --help for usage information" >&2
    exit 1
fi

if [[ -z "$KERNEL_VERSION" ]]; then
    echo "Error: --kernel-version is required" >&2
    echo "Use --help for usage information" >&2
    exit 1
fi

if [[ -z "$ARCH" ]]; then
    echo "Error: --arch is required" >&2
    echo "Use --help for usage information" >&2
    exit 1
fi

if [[ -z "$ENVIRONMENT" ]]; then
    echo "Error: --env is required" >&2
    echo "Use --help for usage information" >&2
    exit 1
fi

# Validate distro
case "$DISTRO" in
    ubuntu|debian|centos|rhel|rocky|almalinux|alpine)
        ;;
    *)
        echo "Error: Unsupported distro: $DISTRO" >&2
        echo "Supported: ubuntu, debian, centos, rhel, rocky, almalinux, alpine" >&2
        exit 1
        ;;
esac

# Validate environment
case "$ENVIRONMENT" in
    local|aws)
        ;;
    *)
        echo "Error: Unsupported environment: $ENVIRONMENT" >&2
        echo "Supported: local, aws" >&2
        exit 1
        ;;
esac

# Validate architecture
case "$ARCH" in
    x86_64|aarch64|arm64)
        ;;
    *)
        echo "Error: Unsupported architecture: $ARCH" >&2
        echo "Supported: x86_64, aarch64, arm64" >&2
        exit 1
        ;;
esac

# Build image name
IMAGE_NAME="${DISTRO}-${VERSION}-${KERNEL_FLAVOR}-${KERNEL_VERSION}-${ARCH}"

echo "╔════════════════════════════════════════════════════════════╗"
echo "║        Generating Cloud-Init Configuration                 ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

# Select template based on distro family
case "$DISTRO" in
    ubuntu|debian)
        USER_DATA_TEMPLATE_FILE="user-data-ubuntu-template.yaml"
        ;;
    centos|rhel|rocky|almalinux)
        USER_DATA_TEMPLATE_FILE="user-data-centos-template.yaml"
        ;;
    alpine)
        USER_DATA_TEMPLATE_FILE="user-data-alpine-template.yaml"
        ;;
    *)
        echo "Error: No template available for distro: $DISTRO" >&2
        echo "Available: ubuntu, debian, centos, rhel, rocky, almalinux, alpine" >&2
        exit 1
        ;;
esac

echo "Configuration:"
echo "  Distro:         ${DISTRO} ${VERSION}"
echo "  Kernel:         ${KERNEL_FLAVOR} ${KERNEL_VERSION}"
echo "  Architecture:   ${ARCH}"
echo "  Environment:    ${ENVIRONMENT}"
echo "  Template:       ${USER_DATA_TEMPLATE_FILE}"
echo "  Image Name:     ${IMAGE_NAME}"
echo ""

# Read templates
if [[ ! -f "${SCRIPT_DIR}/templates/${USER_DATA_TEMPLATE_FILE}" ]]; then
    echo "Error: Template file not found: ${SCRIPT_DIR}/templates/${USER_DATA_TEMPLATE_FILE}" >&2
    exit 1
fi

if [[ ! -f "${SCRIPT_DIR}/templates/meta-data-template.yaml" ]]; then
    echo "Error: Template file not found: ${SCRIPT_DIR}/templates/meta-data-template.yaml" >&2
    exit 1
fi

USER_DATA_TEMPLATE=$(cat "${SCRIPT_DIR}/templates/${USER_DATA_TEMPLATE_FILE}")
META_DATA_TEMPLATE=$(cat "${SCRIPT_DIR}/templates/meta-data-template.yaml")

# Read step files (common sections)
# Step files are already properly indented for runcmd section
DOWNLOAD_SCRIPTS=$(cat "${SCRIPT_DIR}/templates/steps/download-scripts.yaml")
INSTALL_TOOLS=$(cat "${SCRIPT_DIR}/templates/steps/install-tools.yaml")
SETUP_VIRTFS=$(cat "${SCRIPT_DIR}/templates/steps/setup-virtfs.yaml")
FINALIZE=$(cat "${SCRIPT_DIR}/templates/steps/finalize.yaml")
WRITE_VM_CONFIGS=$(cat "${SCRIPT_DIR}/templates/steps/write-vm-configs.yaml")

# Embed kernel installation script (only one we maintain locally)
if [[ ! -f "${SCRIPT_DIR}/scripts/install-kernel.sh" ]]; then
    echo "Error: Kernel installation script not found: ${SCRIPT_DIR}/scripts/install-kernel.sh" >&2
    exit 1
fi

INSTALL_KERNEL=$(cat "${SCRIPT_DIR}/scripts/install-kernel.sh" | sed 's/^/    /')

# Determine username based on distro
case "$DISTRO" in
    ubuntu|debian)
        USERNAME="ubuntu"
        ;;
    centos|rhel|rocky|almalinux)
        USERNAME="ec2-user"
        ;;
    alpine)
        USERNAME="alpine"
        ;;
    *)
        USERNAME="ubuntu"
        ;;
esac

# Replace variables in template
USER_DATA="${USER_DATA_TEMPLATE//\$\{DISTRO\}/${DISTRO}}"
USER_DATA="${USER_DATA//\$\{VERSION\}/${VERSION}}"
USER_DATA="${USER_DATA//\$\{KERNEL_FLAVOR\}/${KERNEL_FLAVOR}}"
USER_DATA="${USER_DATA//\$\{KERNEL_VERSION\}/${KERNEL_VERSION}}"
USER_DATA="${USER_DATA//\$\{ENVIRONMENT\}/${ENVIRONMENT}}"

# Replace variables in step files
# Note: Most variables (DISTRO, VERSION, etc.) are now sourced from /tmp/tracee-vm-env.sh
# at runtime, so we only need to replace variables that aren't in the env file:
# - USERNAME: Not in env file, needs generation-time replacement
SETUP_VIRTFS="${SETUP_VIRTFS//\$\{USERNAME\}/${USERNAME}}"

META_DATA="${META_DATA_TEMPLATE//\$\{DISTRO\}/${DISTRO}}"
META_DATA="${META_DATA//\$\{VERSION\}/${VERSION}}"
META_DATA="${META_DATA//\$\{KERNEL_FLAVOR\}/${KERNEL_FLAVOR}}"
META_DATA="${META_DATA//\$\{KERNEL_VERSION\}/${KERNEL_VERSION}}"
META_DATA="${META_DATA//\$\{ARCH\}/${ARCH}}"

# Replace placeholders with steps using awk for proper multiline handling
USER_DATA=$(echo "$USER_DATA" | awk -v download="$DOWNLOAD_SCRIPTS" -v tools="$INSTALL_TOOLS" -v virtfs="$SETUP_VIRTFS" -v finalize="$FINALIZE" -v kernel="$INSTALL_KERNEL" -v write_vm_configs="$WRITE_VM_CONFIGS" '
/^  # WRITE_VM_CONFIGS_PLACEHOLDER$/ {
    print write_vm_configs
    next
}
/^  # DOWNLOAD_SCRIPTS_PLACEHOLDER$/ {
    print download
    next
}
/^  # INSTALL_TOOLS_PLACEHOLDER$/ {
    print tools
    next
}
/^  # SETUP_VIRTFS_PLACEHOLDER$/ {
    print virtfs
    next
}
/^  # FINALIZE_PLACEHOLDER$/ {
    print finalize
    next
}
/# KERNEL_SCRIPT_PLACEHOLDER/ {
    print "  - |"
    print "    cat > /tmp/install-kernel.sh <<'"'"'KERNEL_SCRIPT'"'"'"
    print kernel
    print "    KERNEL_SCRIPT"
    next
}
{ print }
')

# Write output files
OUTPUT_DIR="${SCRIPT_DIR}/generated"
mkdir -p "${OUTPUT_DIR}"

echo "$USER_DATA" > "${OUTPUT_DIR}/${IMAGE_NAME}-user-data.yaml"
echo "$META_DATA" > "${OUTPUT_DIR}/${IMAGE_NAME}-meta-data.yaml"

echo "✓ Generated files:"
echo "  ${OUTPUT_DIR}/${IMAGE_NAME}-user-data.yaml"
echo "  ${OUTPUT_DIR}/${IMAGE_NAME}-meta-data.yaml"
echo ""
echo "Next steps:"
echo "  1. Create cloud-init ISO from the generated files:"
echo "     cloud-localds ${IMAGE_NAME}-cloud-init.iso \\"
echo "         ${OUTPUT_DIR}/${IMAGE_NAME}-user-data.yaml \\"
echo "         ${OUTPUT_DIR}/${IMAGE_NAME}-meta-data.yaml"
echo ""
echo "  2. Boot VM with the cloud-init ISO and base image"
echo ""
echo "Note: VM images are not included in the repository."
echo "      Download them separately or use the VM management scripts (coming soon)."
echo ""
