
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
    git clone https://github.com/nervosnetwork/godwoken.git $GODWOKEN_DIR
fi

mkdir -p $GODWOKEN_DIR/c/build
cp $SCRIPT_DIR/*generator $SCRIPT_DIR/*validator $GODWOKEN_DIR/c/build
touch $GODWOKEN_DIR/c/build/account_locks/eth-account-lock

cd $PROJECT_ROOT
git submodule update --init --recursive
make all-via-docker

cd $TESTS_DIR
export RUST_BACKTRACE=full
cargo test -- --nocapture
