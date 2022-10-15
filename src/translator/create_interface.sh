#!/bin/bash

modprobe dummy
ip link add enp0s8 type dummy
ip link show enp0s8
