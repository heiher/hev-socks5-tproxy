#!/bin/bash
# make apt slient if you want
function apt { sudo /usr/bin/apt "$@" >/dev/null; }
# function apt { sudo /usr/bin/apt "$@"; }
set -e
SELF_DIR=$(readlink -f "$(dirname "$0")")
echo "$SELF_DIR"

######### set up ABIS
apt -qq -o "Acquire::https::Verify-Peer=false" update && apt -qq -o "Acquire::https::Verify-Peer=false" install -y ca-certificates
apt -qq install build-essential git -y
defaultTargetAbis="x86_64-linux-gnu,i686-linux-gnu,\
aarch64-linux-gnu,arm-linux-gnueabi,arm-linux-gnueabihf,\
mips-linux-gnu,mips64-linux-gnuabi64,mipsel-linux-gnu,mips64-linux-gnuabi64,mips64el-linux-gnuabi64"
TARGET_ABIS=${TARGET_ABIS:-$defaultTargetAbis}
hostABI=$(gcc -dumpmachine)
echo "HOST ABI is:" "$hostABI"
[[ "$hostABI" == "x86_64"* ]] || (
    echo "HOST ABI must be x86_64 !!!"
    exit 1
)

echo "selected cross build ABIS: $TARGET_ABIS"

######### CONFIG
BUILD_DIR=${BUILD_DIR:-"/build"}
OUTPUT_DIR=${OUTPUT_DIR:-"${BUILD_DIR}/target-binary"}
PROJECT_DIR=${CI_PROJECT_DIR:-"./"}

cd "$BUILD_DIR"

IFS=","
for abi in $TARGET_ABIS; do
    IFS=""
    CROSS_PREFIX=${abi}"-"
    
    command -v "${abi}-gcc" || apt -qq install gcc-"${abi}" -y

    ENABLE_STATIC=${ENABLE_STATIC:-""}
    if [[ "$ENABLE_STATIC" == "1" ]]; then
        echo "selected static build"
        targetBinaryDir=${OUTPUT_DIR}/${abi}"-static"
    else
        echo "selected none static build"
        targetBinaryDir=${OUTPUT_DIR}/${abi}
        ENABLE_STATIC=""
    fi
    mkdir -p "${targetBinaryDir}"
    cd "$PROJECT_DIR"
    make CROSS_PREFIX="$CROSS_PREFIX" ENABLE_STATIC="$ENABLE_STATIC" -j $(nproc) >/dev/null || \
    make V=1  CROSS_PREFIX="$CROSS_PREFIX" ENABLE_STATIC="$ENABLE_STATIC" -j 1
    mv bin/* "${targetBinaryDir}"
    make clean
done

apt -qq install file tree -y

tree "$OUTPUT_DIR" || exit 0
file "$OUTPUT_DIR"/*/* || exit 0