#!/bin/bash
set -e

# Workaround for git clone issues in FetchContent
git config --global http.version HTTP/1.1

rm -rf tests/build
mkdir -p tests/build
cd tests/build
cmake ..
make -j$(nproc) unit_tests
./unit_tests
