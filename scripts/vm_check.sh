#!/bin/bash

IMAGE_URL="http://135.181.132.51:8052/vm/base_image_flat.qcow2"
TARGET_DIR="/var/lib/vm"
TARGET_FILE="${TARGET_DIR}/base_image_flat.qcow2"

echo "===== Virtualization + IOMMU Support Check Script ====="


install_deps() {
  set -ex
  local -a pkgs=(
    libvirt-daemon-system
    libvirt-clients
    qemu-system-x86
    virtinst
    virt-manager
    virt-viewer
    libvirt-dev
    python3-libvirt
    qemu-utils
    cloud-utils
    python3-dev
  )

  command -v apt-get >/dev/null 2>&1 || { echo "apt-get not found"; return 1; }

  local -a missing=()
  local p
  for p in "${pkgs[@]}"; do
    dpkg -s "$p" >/dev/null 2>&1 || missing+=("$p")
  done

  if ((${#missing[@]} == 0)); then
    echo "All dependencies already installed."
    return 0
  fi

  echo "Missing packages: ${missing[*]}"
  sudo apt-get update -y
  sudo apt-get install -y "${missing[@]}"
}

install_deps


# 1. CPU virtualization check (VT-x/AMD-V)
echo -n "Checking CPU virtualization support... "
if grep -E 'vmx|svm' /proc/cpuinfo > /dev/null 2>&1; then
    echo "Supported"
else
    echo "Not supported"
    echo "CPU does not support virtualization. Exiting."
    exit 1
fi

# 2. IOMMU check
echo -n "Checking IOMMU support... "

# Check kernel log for IOMMU or DMAR
if dmesg | grep -i -E 'IOMMU|DMAR' > /dev/null 2>&1; then
    echo "Enabled or Present"
else
    # Alternative check: sysfs class iommu
    if [ -d "/sys/class/iommu" ] && [ "$(ls -A /sys/class/iommu)" ]; then
        echo "Present"
    else
        echo "Not detected"
        echo "IOMMU not detected or not enabled."
        # Continue anyway if only virtualization is needed
    fi
fi

# 3. Create target directory
if [ ! -d "$TARGET_DIR" ]; then
    echo "Creating directory: $TARGET_DIR"
    mkdir -p "$TARGET_DIR"
    if [ $? -ne 0 ]; then
        echo "Failed to create directory. Check permissions."
        exit 1
    fi
fi

# 4. Detect download tool
DOWNLOAD_TOOL=""
if command -v wget > /dev/null 2>&1; then
    DOWNLOAD_TOOL="wget"
elif command -v curl > /dev/null 2>&1; then
    DOWNLOAD_TOOL="curl"
else
    echo "Neither wget nor curl is installed. Install one first."
    exit 1
fi

# 5. Download image
echo "Downloading image with $DOWNLOAD_TOOL..."
if [ "$DOWNLOAD_TOOL" = "wget" ]; then
    wget -O "$TARGET_FILE" "$IMAGE_URL"
else
    curl -o "$TARGET_FILE" "$IMAGE_URL"
fi

# Check success
if [ $? -eq 0 ]; then
    echo "Download succeeded: $TARGET_FILE"
else
    echo "Download failed. Check URL or network."
    exit 1
fi

echo "Done."
