set -x
set -e

SCRIPT_DIR=$(realpath $(dirname $0))
PROJECT_ROOT=$(dirname $(dirname $SCRIPT_DIR))
TESTS_DIR=$PROJECT_ROOT/polyjuice-tests
DEPS_DIR=$PROJECT_ROOT/integration-test
GODWOKEN_DIR=$DEPS_DIR/godwoken
ETHEREUM_TEST_DIR=$DEPS_DIR/ethereum-tests

mkdir -p $DEPS_DIR
if [ -d "$GODWOKEN_DIR" ]
then
    echo "godwoken project already exists"
else
    git clone --depth=1 https://github.com/nervosnetwork/godwoken.git $GODWOKEN_DIR
fi
# clone ethereum/test
if [ -d "$ETHEREUM_TEST_DIR" ]
then
    echo "ethereum test project already exists"
else
    git clone --depth=1 https://github.com/ethereum/tests.git $ETHEREUM_TEST_DIR
fi
cd $GODWOKEN_DIR
git fetch origin develop
git checkout FETCH_HEAD 
git submodule update --init --recursive --depth=1

cd $PROJECT_ROOT
git submodule update --init --recursive --depth=1
make all-via-docker

cd $TESTS_DIR
export RUST_BACKTRACE=full
cargo test --lib -- --nocapture
# TODO: cargo bench | egrep -v debug

# run ethereum test
RUST_LOG=info,gw_generator=debug cargo test --test ethereum_test  -- ethereum_test --nocapture

