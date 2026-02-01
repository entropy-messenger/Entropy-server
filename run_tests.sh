#!/bin/bash
set -e

# Workaround for git clone issues in FetchContent
git config --global http.version HTTP/1.1

rm -rf build
mkdir -p build
cd build
cmake ..
make -j$(nproc) unit_tests
./tests/unit_tests
