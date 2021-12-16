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
    git clone --depth=100 -b generator-ahead-of-time-compilation https://github.com/flouse/godwoken.git $GODWOKEN_DIR
fi
cd $GODWOKEN_DIR
git checkout a6405ad140f96f1d7914e18b66c1249a9a4632d6 # Commit on Thu Dec 9 07:10:43 2021 +0000
git submodule update --init --recursive --depth=1

cd $PROJECT_ROOT
git submodule update --init --recursive --depth=1
make all-via-docker

# fetch godwoken-scripts from godwoken-prebuilds image,
# including meta-contract and sudt-contract
GW_SCRIPTS_DIR=$PROJECT_ROOT/build
docker pull nervos/godwoken-prebuilds:latest
mkdir -p $GW_SCRIPTS_DIR && echo "Create dir"
docker run --rm -v $GW_SCRIPTS_DIR:/build-dir \
  nervos/godwoken-prebuilds:latest \
  cp -r /scripts/godwoken-scripts /build-dir \
  && echo "Copy godwoken-scripts"

cd $TESTS_DIR
export RUST_BACKTRACE=full
cargo test -- --nocapture
# cargo bench | egrep -v debug
