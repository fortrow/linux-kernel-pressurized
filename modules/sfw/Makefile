# SPDX-License-Identifier: GPL-2.0
obj-m += sfw.o
sfw-y := sfw_main.o sfw_nat_fwd.o

KDIR ?= $(abspath $(dir $(lastword $(MAKEFILE_LIST)))/../../build)
SRC_ROOT ?= $(abspath $(dir $(lastword $(MAKEFILE_LIST)))/../..)
ccflags-y += -I$(SRC_ROOT)/include/uapi -I$(SRC_ROOT)/include

all:
	$(MAKE) -C "$(KDIR)" M="$(CURDIR)" modules

clean:
	$(MAKE) -C "$(KDIR)" M="$(CURDIR)" clean
