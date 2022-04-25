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
# checkout https://github.com/nervosnetwork/godwoken/pull/659/head
git fetch origin ed9d3ab716ea5d5a8f22f5ea7e6c90e23b6a49a8
git checkout FETCH_HEAD 
git submodule update --init --recursive --depth=1

cd $PROJECT_ROOT
git submodule update --init --recursive --depth=1
make all-via-docker

cd $TESTS_DIR
export RUST_BACKTRACE=full
cargo test -- --nocapture
# TODO: cargo bench | egrep -v debug
