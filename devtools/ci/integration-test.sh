set -x
set -e

SCRIPT_DIR=$(realpath $(dirname $0))
PROJECT_ROOT=$(dirname $(dirname $SCRIPT_DIR))
TESTS_DIR=$PROJECT_ROOT/polyjuice-tests
DEPS_DIR=$PROJECT_ROOT/integration-test
GODWOKEN_DIR=$DEPS_DIR/godwoken

mkdir -p $DEPS_DIR
if [ -d "$GODWOKEN_DIR" ]
then
    echo "godwoken project already exists"
else
    git clone --depth=1 https://github.com/nervosnetwork/godwoken.git $GODWOKEN_DIR
fi
cd $GODWOKEN_DIR
# https://github.com/nervosnetwork/godwoken/releases/tag/v0.10.4
git fetch origin v0.10.4
git checkout FETCH_HEAD
git submodule update --init --recursive --depth=1

cd $PROJECT_ROOT
git submodule update --init --recursive --depth=1
make all-via-docker

# fetch godwoken-scripts from godwoken-prebuilds image,
# including meta-contract and sudt-contract
GW_SCRIPTS_DIR=$PROJECT_ROOT/build
mkdir -p $GW_SCRIPTS_DIR && echo "Create dir"
IMAGE=nervos/godwoken-prebuilds:v0.10.4
docker pull $IMAGE
docker run --rm -v $GW_SCRIPTS_DIR:/build-dir $IMAGE \
  cp -r /scripts/godwoken-scripts /build-dir \
  && echo "Copy godwoken-scripts"

cd $TESTS_DIR
export RUST_BACKTRACE=full
cargo test -- --nocapture
# cargo bench | egrep -v debug
