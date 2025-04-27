#!/bin/bash

set -e
trap 'echo "An error occurred. Exiting."; exit 1' ERR
INPUT_DEVICE="/dev/urandom"
PASSES=1
BLOCK_SIZE="1M"

function usage {
  echo "Usage: $0 [OPTIONS] /dev/sdX"
  echo
  echo "OPTIONS:"
  echo "  -p, --passes <n>     Number of times to overwrite (default: 1)"
  echo "  -b, --bs <size>      Block size for dd (default: 1M)"
  echo "  -z, --zero           Use /dev/zero instead of /dev/urandom"
  echo "  -h, --help           Display this help message"
  echo
  echo "Examples:"
  echo "  $0 -p 3 -b 4M /dev/sdX    Overwrite 3 times with a 4M block size using /dev/urandom"
  echo "  $0 -z /dev/sdX            Overwrite 1 time using /dev/zero"
  exit 1
}
while [[ $# -gt 0 ]]; do
  case "$1" in
    -p|--passes)
      PASSES="$2"
      shift 2
      ;;
    -b|--bs)
      BLOCK_SIZE="$2"
      shift 2
      ;;
    -z|--zero)
      INPUT_DEVICE="/dev/zero"
      shift
      ;;
    -h|--help)
      usage
      ;;
    *)
      DISK="$1"
      shift
      ;;
  esac
done

if [ -z "${DISK:-}" ]; then
  usage
fi

if [ "$EUID" -ne 0 ]; then
  echo "Please run as root."
  exit 1
fi

if [ ! -b "$DISK" ]; then
  echo "Error: $DISK is not a valid block device."
  exit 1
fi

if mount | grep -q "$DISK"; then
  echo "Error: $DISK is mounted. Please unmount it first."
  exit 1
fi

echo "================================================================================"
cat << 'EOF'

    _   _________    ____________  __  _______  ____  ______
   / | / / ____/ |  / / ____/ __ \/  |/  / __ \/ __ \/ ____/
  /  |/ / __/  | | / / __/ / /_/ / /|_/ / / / / /_/ / __/   
 / /|  / /___  | |/ / /___/ _, _/ /  / / /_/ / _, _/ /___   
/_/ |_/_____/  |___/_____/_/ |_/_/  /_/\____/_/ |_/_____/   
                                                            

EOF
echo "================================================================================"
echo "WARNING: This operation will irreversibly overwrite $DISK with '$INPUT_DEVICE'."
echo "Number of passes: $PASSES"
echo "Block size: $BLOCK_SIZE"
echo "ALL DATA ON THIS DEVICE WILL BE PERMANENTLY LOST. Proceed with caution!"
echo "================================================================================"

read -p "Type YES to continue: " confirm
if [ "$confirm" != "YES" ]; then
  echo "Aborted."
  exit 1
fi

for (( pass=1; pass<=PASSES; pass++ )); do
  echo "Starting pass $pass of $PASSES using $INPUT_DEVICE..."
  dd if="$INPUT_DEVICE" of="$DISK" bs="$BLOCK_SIZE" status=progress conv=fdatasync
  sync
done

echo "Done. $DISK has been destroyed $PASSES time(s) using $INPUT_DEVICE."
