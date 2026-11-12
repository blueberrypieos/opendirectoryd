/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 The Blueberry Pie OS Authors
 */
#ifndef OD_PLIST_H
#define OD_PLIST_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

enum pl_type {
	PL_DICT,
	PL_ARRAY,
	PL_STRING,
	PL_DATA,
	PL_INT,
	PL_BOOL,
	PL_REAL,
};

typedef struct pl pl_t;

struct pl {
	enum pl_type type;
	size_t count;
	size_t cap;
	char **keys;
	pl_t **items;
	uint8_t *bytes;
	size_t len;
	int64_t i;
	double r;
};

pl_t *pl_dict(void);
pl_t *pl_array(void);
pl_t *pl_string(const char *s);
pl_t *pl_string_n(const char *s, size_t len);
pl_t *pl_data(const void *p, size_t len);
pl_t *pl_int(int64_t v);
pl_t *pl_bool(bool v);
pl_t *pl_copy(const pl_t *p);
void pl_free(pl_t *p);

bool pl_equal(const pl_t *a, const pl_t *b);

void pl_dict_set(pl_t *d, const char *key, pl_t *v);
pl_t *pl_dict_get(const pl_t *d, const char *key);
bool pl_dict_remove(pl_t *d, const char *key);
pl_t *pl_dict_take(pl_t *d, const char *key);

void pl_array_append(pl_t *a, pl_t *v);
pl_t *pl_array_get(const pl_t *a, size_t i);
void pl_array_remove(pl_t *a, size_t i);

const char *pl_str(const pl_t *p);
bool pl_is(const pl_t *p, enum pl_type t);

int pl_bplist_write(const pl_t *p, uint8_t **out, size_t *len);
pl_t *pl_bplist_read(const uint8_t *buf, size_t len);

void od_wipe(void *p, size_t len);

#endif
