/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 The Blueberry Pie OS Authors
 *
 * usage: dscl -f DIR -create path [key [value ...]]
 *        dscl -f DIR -append path key value ...
 *        dscl -f DIR -delete path [key [value ...]]
 *        dscl -f DIR -passwd path [new_password]
 *
 * dscl's commands on the local node in DIR, a dslocal node directory such
 * as /var/db/dslocal/nodes/Default, without opendirectoryd: the same code
 * runs in dscl, with the caller's credentials. -passwd without a password
 * asks for it twice on the terminal, or reads one line from standard
 * input if that is not a terminal.
 */
#include <sys/stat.h>

#include <limits.h>
#include <readpassphrase.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "od.h"
#include "offline.h"

struct reply {
	uint64_t error;
	pl_t *plist;
};

static struct od od;
static uint8_t node[16];
static const char *cmd_name, *path_arg;

static void
log_message(int level, const char *fmt, ...)
{
	va_list ap;

	if (level > OD_LOG_WARNING) {
		return;
	}
	va_start(ap, fmt);
	fprintf(stderr, "dscl: ");
	vfprintf(stderr, fmt, ap);
	fputc('\n', stderr);
	va_end(ap);
}

static time_t
now(void)
{
	return time(NULL);
}

static void
changed(void)
{
}

static void
capture(void *ctx, uint64_t error, bool complete, const pl_t *reply)
{
	struct reply *r = ctx;

	(void)complete;
	r->error = error;
	pl_free(r->plist);
	r->plist = reply != NULL ? pl_copy(reply) : NULL;
}

static uint64_t
call(struct reply *r, const uint8_t *nd, const char *fn, size_t n, ...)
{
	static const uint8_t zero[16];
	struct od_caller caller = { geteuid(), getpid(), NULL };
	pl_t *req = pl_dict(), *params = pl_array(), *slot, *v;
	uint8_t *data;
	size_t len, i;
	va_list ap;

	va_start(ap, n);
	for (i = 0; i < n; i++) {
		v = va_arg(ap, pl_t *);
		slot = pl_array();
		if (v != NULL) {
			pl_array_append(slot, v);
		}
		pl_array_append(params, slot);
	}
	va_end(ap);
	pl_dict_set(req, "funcname", pl_string(fn));
	pl_dict_set(req, "parameters", params);
	if (pl_bplist_write(req, &data, &len) != 0) {
		pl_free(req);
		return ODE_PARAMETER;
	}
	pl_free(req);
	r->error = ODE_DAEMON;
	od_api(&od, &caller, zero, nd != NULL ? nd : zero, data, len, capture, r);
	free(data);
	return r->error;
}

static void
fail(uint64_t error)
{
	fprintf(stderr, "dscl: %s %s: error %llu\n", cmd_name, path_arg, (unsigned long long)error);
	exit(1);
}

static void
check(uint64_t error)
{
	if (error != 0) {
		fail(error);
	}
}

static char *
full_attribute(const char *key)
{
	char buf[512];
	bool known;

	if (strncmp(key, OD_STD, strlen(OD_STD)) == 0 || strncmp(key, OD_NATIVE, strlen(OD_NATIVE)) == 0) {
		return strdup(key);
	}
	snprintf(buf, sizeof(buf), "%s%s", OD_STD, key);
	if (attr_is_virtual(buf) || (attr_key(buf, &known) != NULL && known)) {
		return strdup(buf);
	}
	snprintf(buf, sizeof(buf), "%s%s", OD_NATIVE, key);
	return strdup(buf);
}

static char *
read_password(void)
{
	char buf[1024], again[1024];
	size_t n;

	if (!isatty(STDIN_FILENO)) {
		if (fgets(buf, sizeof(buf), stdin) == NULL) {
			fprintf(stderr, "dscl: no password on standard input\n");
			exit(1);
		}
		n = strcspn(buf, "\r\n");
		if (buf[n] == '\0' && !feof(stdin)) {
			fprintf(stderr, "dscl: the password is too long\n");
			exit(1);
		}
		buf[n] = '\0';
		return strdup(buf);
	}
	if (readpassphrase("New Password:", buf, sizeof(buf), RPP_ECHO_OFF | RPP_REQUIRE_TTY) == NULL ||
	    readpassphrase("Retype New Password:", again, sizeof(again), RPP_ECHO_OFF | RPP_REQUIRE_TTY) == NULL) {
		fprintf(stderr, "dscl: cannot read the password\n");
		exit(1);
	}
	if (strlen(buf) >= sizeof(buf) - 1 || strlen(again) >= sizeof(again) - 1) {
		fprintf(stderr, "dscl: the password is too long\n");
		exit(1);
	}
	if (strcmp(buf, again) != 0) {
		fprintf(stderr, "dscl: the passwords differ\n");
		exit(1);
	}
	return strdup(buf);
}

int
offline_main(const char *dir, const char *cmd, const char *path, const char *type, const char *name,
    int argc, char **argv)
{
	struct reply r = { 0, NULL };
	const pl_t *v;
	char *attr;
	int i;

	cmd_name = cmd;
	path_arg = path;
	od.shells_path = "/etc/shells";
	od.passwd_path = "/etc/passwd";
	od.master_passwd_path = "/etc/master.passwd";
	od.group_path = "/etc/group";
	od.iterations = OD_ITERATIONS;
	od.changed = changed;
	od.log = log_message;
	od.now = now;
	char sub[PATH_MAX];
	struct stat st;

	for (i = 0; i < RT_COUNT; i++) {
		snprintf(sub, sizeof(sub), "%s/%s", dir, rtype_dir((enum rtype)i));
		if (stat(sub, &st) != 0 || !S_ISDIR(st.st_mode)) {
			fprintf(stderr, "dscl: %s: not a dslocal node\n", dir);
			return 1;
		}
	}
	if (od_init(&od, dir) != 0) {
		fprintf(stderr, "dscl: %s: not a dslocal node\n", dir);
		return 1;
	}
	check(call(&r, NULL, "ODNodeCreateWithName", 1, pl_string(OD_LOCAL_NODE)));
	v = pl_array_get(pl_array_get(pl_dict_get(r.plist, "results"), 0), 0);
	if (!pl_is(v, PL_DATA) || v->len != 16) {
		fail(ODE_NODE_INVALID);
	}
	memcpy(node, v->bytes, 16);

	if (strcmp(cmd, "create") == 0) {
		if (call(&r, node, "ODNodeCreateRecord", 3, pl_string(type), pl_string(name), NULL) != 0 &&
		    r.error != ODE_ALREADY_EXISTS) {
			fail(r.error);
		}
		if (argc > 0) {
			pl_t *values = pl_array();

			if (argc == 1) {
				pl_array_append(values, pl_string(""));
			}
			for (i = 1; i < argc; i++) {
				pl_array_append(values, pl_string(argv[i]));
			}
			attr = full_attribute(argv[0]);
			check(call(&r, node, "ODRecordSetValue", 5, pl_string(type), pl_string(name), NULL,
			    pl_string(attr), values));
			free(attr);
		}
	} else if (strcmp(cmd, "append") == 0) {
		attr = full_attribute(argv[0]);
		for (i = 1; i < argc; i++) {
			check(call(&r, node, "ODRecordAddValue", 5, pl_string(type), pl_string(name), NULL,
			    pl_string(attr), pl_string(argv[i])));
		}
		free(attr);
	} else if (strcmp(cmd, "delete") == 0) {
		if (argc == 0) {
			check(call(&r, node, "ODRecordDelete", 2, pl_string(type), pl_string(name)));
		} else {
			attr = full_attribute(argv[0]);
			if (argc == 1) {
				check(call(&r, node, "ODRecordSetValue", 5, pl_string(type), pl_string(name), NULL,
				    pl_string(attr), pl_array()));
			}
			for (i = 1; i < argc; i++) {
				check(call(&r, node, "ODRecordRemoveValue", 5, pl_string(type), pl_string(name),
				    NULL, pl_string(attr), pl_string(argv[i])));
			}
			free(attr);
		}
	} else if (strcmp(cmd, "passwd") == 0) {
		char *pw = argc == 1 ? strdup(argv[0]) : read_password();

		check(call(&r, node, "ODRecordChangePassword", 5, pl_string(type), pl_string(name), NULL, NULL,
		    pl_string(pw)));
		memset(pw, 0, strlen(pw));
		free(pw);
	} else {
		fprintf(stderr, "dscl: -%s is not available with -f\n", cmd);
		return 2;
	}
	pl_free(r.plist);
	od_free(&od);
	return 0;
}
