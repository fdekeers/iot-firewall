#!/bin/bash

mkdir $GITHUB_WORKSPACE/build
mkdir $GITHUB_WORKSPACE/bin
cd $GITHUB_WORKSPACE/build
cmake ..
cmake --build .
