CFILES := drvfpgasoc.c

obj-m := fpgasoc.o
fpgasoc-objs := $(CFILES:.c=.o)

thisdir := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
incdir := $(thisdir)/include

ccflags-y += -std=gnu99 -Wall -Wno-declaration-after-statement -I$(incdir) -march=armv7-a

DESTDIR ?= /
prefix ?= 
target_kern_ver ?= $(shell uname -r)
MODULE_INST_PATH := lib/modules/$(target_kern_ver)/extramodules
MODULE_CONF_INST_PATH := etc/modules-load.d
INCLUDE_INST_PATH := usr/include

.PHONY: all
all:
	make -C /lib/modules/$(target_kern_ver)/build M=$(thisdir)

.PHONY: install
install: all
	install -v -D -t $(DESTDIR)/$(prefix)/$(MODULE_INST_PATH)/ $(obj-m:.o=.ko)
	install -v -D -t $(DESTDIR)/$(prefix)/$(MODULE_CONF_INST_PATH)/ conf/$(obj-m:.o=.conf)
	install -v -D -t $(DESTDIR)/$(prefix)/$(INCLUDE_INST_PATH) include/*

.PHONY: clean
clean:
	make -C /lib/modules/$(target_kern_ver)/build M=$(thisdir) clean
