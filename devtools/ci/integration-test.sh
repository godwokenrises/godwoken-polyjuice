
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
git fetch origin --tags
git checkout v0.6.0-rc3
git submodule update --init --recursive

cd tests-deps/godwoken-scripts/c
git checkout v0.8.0-rc2
git submodule update --init --recursive
make all-via-docker

cd $PROJECT_ROOT
git submodule update --init --recursive
make all-via-docker

cd $TESTS_DIR
export RUST_BACKTRACE=full
cargo test -- --nocapture
cargo bench
