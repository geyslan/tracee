#!/bin/bash
# Start Tracee VM with virtiofs shared directories
#
# This script:
# 1. Starts virtiofsd daemons for host directory sharing
# 2. Waits for sockets to be ready
# 3. Launches QEMU with virtiofs support

set -e

# Configuration
VM_NAME="${1:-ubuntu-22.04-generic-5.19.0-50-x86_64}"
VM_DIR="${VM_DIR:-${HOME}/vms}"
TRACEE_DIR="${TRACEE_DIR:-${HOME}/code/tracee}"
VIRTIOFSD="${VIRTIOFSD:-/usr/libexec/virtiofsd}"

# VM resources
VM_RAM="${VM_RAM:-4G}"
VM_CPUS="${VM_CPUS:-4}"
SSH_PORT="${SSH_PORT:-2222}"

# Socket and log paths
TRACEE_SOCK="/tmp/vhost-tracee.sock"
VIRTIOFSD_LOG="/tmp/virtiofsd-tracee.log"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "╔════════════════════════════════════════════════════════════╗"
echo "║        Starting Tracee VM with Virtiofs                    ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

# Check if virtiofsd exists
if ! command -v "${VIRTIOFSD}" &> /dev/null; then
    echo -e "${RED}Error: virtiofsd not found at ${VIRTIOFSD}${NC}"
    echo "Try: which virtiofsd || find /usr -name virtiofsd 2>/dev/null"
    echo ""
    echo "Install with:"
    echo "  Fedora: sudo dnf install qemu-virtiofsd"
    echo "  Ubuntu: sudo apt install qemu-system-gui"
    exit 1
fi

# Check if VM image exists
if [ ! -f "${VM_DIR}/${VM_NAME}.qcow2" ]; then
    echo -e "${RED}Error: VM image not found: ${VM_DIR}/${VM_NAME}.qcow2${NC}"
    exit 1
fi

# Check if cloud-init ISO exists
if [ ! -f "${VM_DIR}/${VM_NAME}-cloud-init.iso" ]; then
    echo -e "${YELLOW}Warning: cloud-init ISO not found: ${VM_DIR}/${VM_NAME}-cloud-init.iso${NC}"
    echo "VM will boot without cloud-init configuration"
fi

# Check if shared directories exist
if [ ! -d "${TRACEE_DIR}" ]; then
    echo -e "${RED}Error: Tracee directory not found: ${TRACEE_DIR}${NC}"
    exit 1
fi

# Clean up old sockets and logs
rm -f "${TRACEE_SOCK}"
rm -f "${VIRTIOFSD_LOG}"

# Trap to clean up on exit
cleanup() {
    echo ""
    echo "Cleaning up..."
    pkill -P $$ virtiofsd 2>/dev/null || true
    rm -f "${TRACEE_SOCK}"
    echo "Done."
}
trap cleanup EXIT INT TERM

echo "Configuration:"
echo "  VM Name:        ${VM_NAME}"
echo "  VM Image:       ${VM_DIR}/${VM_NAME}.qcow2"
echo "  RAM:            ${VM_RAM}"
echo "  CPUs:           ${VM_CPUS}"
echo "  SSH Port:       localhost:${SSH_PORT}"
echo "  Tracee Dir:     ${TRACEE_DIR}"
echo "  Host UID:GID:   $(id -u):$(id -g)"
echo "  VM UID:GID:     1000:1000 (mapped to host)"
echo ""

# Start virtiofsd for tracee
echo "Starting virtiofsd for tracee..."
echo "  Log file: ${VIRTIOFSD_LOG}"
"${VIRTIOFSD}" \
    --socket-path="${TRACEE_SOCK}" \
    --shared-dir="${TRACEE_DIR}" \
    --cache=never \
    --sandbox=none \
    --inode-file-handles=never \
    --translate-uid="map:1000:$(id -u):1" \
    --translate-gid="map:1000:$(id -g):1" \
    >> "${VIRTIOFSD_LOG}" 2>&1 &
VIRTIOFSD_PID=$!

# Wait for socket to be created
echo "Waiting for virtiofsd socket..."
for i in {1..15}; do
    if [ -S "${TRACEE_SOCK}" ]; then
        # Verify virtiofsd is still running
        if ! kill -0 "${VIRTIOFSD_PID}" 2>/dev/null; then
            echo -e "${RED}Error: virtiofsd process died${NC}"
            echo "Check log: ${VIRTIOFSD_LOG}"
            tail -20 "${VIRTIOFSD_LOG}"
            exit 1
        fi
        echo -e "${GREEN}✓ Socket ready! (PID: ${VIRTIOFSD_PID})${NC}"
        break
    fi
    
    if [ $i -eq 15 ]; then
        echo -e "${RED}Error: Timeout waiting for socket${NC}"
        echo "Check log: ${VIRTIOFSD_LOG}"
        tail -20 "${VIRTIOFSD_LOG}"
        exit 1
    fi
    
    sleep 1
done

# Verify socket
ls -lh "${TRACEE_SOCK}"
echo ""

# Build QEMU command
QEMU_CMD=(
    qemu-system-x86_64
    -enable-kvm
    -cpu host
    -m "${VM_RAM}"
    -smp "${VM_CPUS}"
    # Shared memory for virtiofs
    -object "memory-backend-memfd,id=mem,size=${VM_RAM},share=on"
    -numa node,memdev=mem
    # Virtiofs for tracee
    -chardev "socket,id=char-tracee,path=${TRACEE_SOCK}"
    -device vhost-user-fs-pci,chardev=char-tracee,tag=tracee
    # Disk, networking, etc.
    -drive "file=${VM_DIR}/${VM_NAME}.qcow2,format=qcow2,if=virtio"
)

# Add cloud-init ISO if exists
if [ -f "${VM_DIR}/${VM_NAME}-cloud-init.iso" ]; then
    QEMU_CMD+=(-cdrom "${VM_DIR}/${VM_NAME}-cloud-init.iso")
fi

QEMU_CMD+=(
    -net nic,model=virtio
    -net "user,hostfwd=tcp::${SSH_PORT}-:22"
    -nographic
    -serial mon:stdio
)

echo "Starting QEMU..."
echo ""
echo -e "${GREEN}VM is starting...${NC}"
echo "SSH access: ssh -i ~/.ssh/tracee_team_ed25519 -p ${SSH_PORT} ubuntu@localhost"
echo ""
echo "Debug info:"
echo "  virtiofsd PID: ${VIRTIOFSD_PID}"
echo "  virtiofsd log: ${VIRTIOFSD_LOG}"
echo ""
echo "Press Ctrl+A then X to quit QEMU"
echo "════════════════════════════════════════════════════════════"
echo ""

# Start QEMU (foreground)
exec "${QEMU_CMD[@]}"
