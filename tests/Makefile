# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 The Blueberry Pie OS Authors
#
# usage: make -C tests check

CC ?= cc
O ?= build
SRC := ../opendirectoryd
CORE := plist util attrmap store shadow backoff lookup api resolver
CFLAGS := -std=gnu11 -O1 -g -Wall -Wextra -Wno-unused-parameter -Werror \
	-fsanitize=address,undefined -fno-omit-frame-pointer -U_FORTIFY_SOURCE -Ihost -I$(SRC)
LIBCRYPTO ?= $(firstword $(wildcard /usr/lib/x86_64-linux-gnu/libcrypto.so.3 /usr/lib/aarch64-linux-gnu/libcrypto.so.3 /usr/lib/libcrypto.so.3))

$(O)/test_od: test_od.c host/cc_shim.c host/sys/kauth.h $(CORE:%=$(SRC)/%.c) $(SRC)/od.h $(SRC)/plist.h
	@mkdir -p $(O)
	$(CC) $(CFLAGS) test_od.c host/cc_shim.c $(CORE:%=$(SRC)/%.c) $(LIBCRYPTO) \
		-Wl,--wrap=readdir,--wrap=opendir,--wrap=fstatat,--wrap=read,--wrap=clock_gettime -o $@

check: $(O)/test_od
	$(O)/test_od
	python3 test_tools.py $(O)/test_od

clean:
	rm -rf $(O)

.PHONY: check clean
