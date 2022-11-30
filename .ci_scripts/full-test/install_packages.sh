#!/bin/bash

apt update
apt install gcc make cmake libcunit1 libcunit1-dev net-tools nftables libnetfilter-queue-dev
pip install -r $GITHUB_WORKSPACE/requirements.txt
