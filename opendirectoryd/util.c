/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 The Blueberry Pie OS Authors
 */
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "od.h"

static const char *const rtype_names[RT_COUNT] = {
	OD_RECSTD "Users",
	OD_RECSTD "Groups",
};

static const char *const rtype_dirs[RT_COUNT] = {
	"users",
	"groups",
};

const char *
rtype_name(enum rtype t)
{
	return rtype_names[t];
}

const char *
rtype_dir(enum rtype t)
{
	return rtype_dirs[t];
}

int
rtype_from_name(const char *name, enum rtype *t)
{
	int i;

	if (name == NULL) {
		return -1;
	}
	for (i = 0; i < RT_COUNT; i++) {
		if (strcmp(name, rtype_names[i]) == 0) {
			*t = (enum rtype)i;
			return 0;
		}
	}
	return -1;
}

static int
hexval(int c)
{
	if (c >= '0' && c <= '9') {
		return c - '0';
	}
	c = tolower(c);
	if (c >= 'a' && c <= 'f') {
		return c - 'a' + 10;
	}
	return -1;
}

bool
uuid_parse_text(const char *s, uint8_t uu[16])
{
	int i, n = 0, hi, lo;

	if (s == NULL || strlen(s) != 36) {
		return false;
	}
	for (i = 0; i < 36;) {
		if (i == 8 || i == 13 || i == 18 || i == 23) {
			if (s[i] != '-') {
				return false;
			}
			i++;
			continue;
		}
		hi = hexval((unsigned char)s[i]);
		lo = hexval((unsigned char)s[i + 1]);
		if (hi < 0 || lo < 0) {
			return false;
		}
		uu[n++] = (uint8_t)(hi << 4 | lo);
		i += 2;
	}
	return n == 16;
}

void
uuid_text(const uint8_t uu[16], char out[37])
{
	snprintf(out, 37, "%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
	    uu[0], uu[1], uu[2], uu[3], uu[4], uu[5], uu[6], uu[7], uu[8], uu[9], uu[10], uu[11],
	    uu[12], uu[13], uu[14], uu[15]);
}

void
uuid_random(uint8_t uu[16])
{
	arc4random_buf(uu, 16);
	uu[6] = (uint8_t)((uu[6] & 0x0F) | 0x40);
	uu[8] = (uint8_t)((uu[8] & 0x3F) | 0x80);
}

bool
parse_id(const char *s, uint32_t *id)
{
	char *end;
	long long v;

	if (s == NULL || *s == '\0' || isspace((unsigned char)*s)) {
		return false;
	}
	errno = 0;
	v = strtoll(s, &end, 10);
	if (errno != 0 || *end != '\0' || v < INT32_MIN || v > UINT32_MAX) {
		return false;
	}
	*id = (uint32_t)v;
	return true;
}

bool
name_in_file(const char *path, const char *name)
{
	char line[1024];
	size_t n = strlen(name);
	bool found = false;
	FILE *f;

	if (path == NULL || (f = fopen(path, "r")) == NULL) {
		return false;
	}
	while (!found && fgets(line, sizeof(line), f) != NULL) {
		if (line[0] == '#' || line[0] == '+' || line[0] == '-') {
			continue;
		}
		if (strncmp(line, name, n) == 0 && line[n] == ':') {
			found = true;
		}
	}
	fclose(f);
	return found;
}
