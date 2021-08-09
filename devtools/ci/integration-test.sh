
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
    # git clone --depth=1 https://github.com/nervosnetwork/godwoken.git $GODWOKEN_DIR
    git clone -b pprof --depth=1 https://github.com/Flouse/godwoken.git $GODWOKEN_DIR
fi

cd $GODWOKEN_DIR
# git pull -r origin master
git submodule update --init --recursive

cd tests-deps/godwoken-scripts/c
# git pull -r origin master
git checkout 33d93f9
git submodule update --init --recursive
make all-via-docker

cd $PROJECT_ROOT
git submodule update --init --recursive
make all-via-docker

cd $TESTS_DIR
export RUST_BACKTRACE=full
cargo test -- --nocapture
cargo bench | egrep -v debug

cd $PROJECT_ROOT
make clean-via-docker  
make all-via-docker-in-debug-mode
