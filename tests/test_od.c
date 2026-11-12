/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 The Blueberry Pie OS Authors
 *
 * usage: test_od
 *        test_od dump FILE
 *        test_od roundtrip IN OUT
 *        test_od verify RECORD PASSWORD
 *        test_od shadow PASSWORD ITERATIONS OUT
 */
#include <sys/kauth.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <CommonCrypto/CommonKeyDerivation.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "od.h"

static int failures;
static int checks;
static time_t fake_now = 1000000;
static int changes;

#define CHECK(cond) check((cond), #cond, __FILE__, __LINE__)

static void
check(bool ok, const char *what, const char *file, int line)
{
	checks++;
	if (!ok) {
		failures++;
		fprintf(stderr, "FAIL %s:%d: %s\n", file, line, what);
	}
}

static void
quiet_log(int level, const char *fmt, ...)
{
	(void)level;
	(void)fmt;
}

static time_t
test_now(void)
{
	return fake_now;
}

static void
test_changed(void)
{
	changes++;
}

static uint8_t *
read_file(const char *path, size_t *len)
{
	struct stat st;
	uint8_t *buf;
	FILE *f = fopen(path, "rb");

	if (f == NULL || fstat(fileno(f), &st) != 0) {
		return NULL;
	}
	buf = malloc((size_t)st.st_size + 1);
	*len = fread(buf, 1, (size_t)st.st_size, f);
	fclose(f);
	return buf;
}

static void
write_file(const char *path, const void *p, size_t len)
{
	FILE *f = fopen(path, "wb");

	fwrite(p, 1, len, f);
	fclose(f);
}

static void
dump(const pl_t *p, FILE *out)
{
	size_t i, j, *order;

	switch (p->type) {
	case PL_STRING:
		fputc('"', out);
		for (i = 0; i < p->len; i++) {
			if (p->bytes[i] == '"' || p->bytes[i] == '\\') {
				fputc('\\', out);
			}
			fputc(p->bytes[i], out);
		}
		fputc('"', out);
		break;
	case PL_DATA:
		fputc('<', out);
		for (i = 0; i < p->len; i++) {
			fprintf(out, "%02x", p->bytes[i]);
		}
		fputc('>', out);
		break;
	case PL_INT:
		fprintf(out, "%lld", (long long)p->i);
		break;
	case PL_BOOL:
		fputs(p->i ? "true" : "false", out);
		break;
	case PL_REAL:
		fprintf(out, "%.17g", p->r);
		break;
	case PL_ARRAY:
		fputc('[', out);
		for (i = 0; i < p->count; i++) {
			if (i > 0) {
				fputc(',', out);
			}
			dump(p->items[i], out);
		}
		fputc(']', out);
		break;
	case PL_DICT:
		order = malloc((p->count + 1) * sizeof(*order));
		for (i = 0; i < p->count; i++) {
			order[i] = i;
		}
		for (i = 0; i < p->count; i++) {
			for (j = i + 1; j < p->count; j++) {
				if (strcmp(p->keys[order[j]], p->keys[order[i]]) < 0) {
					size_t t = order[i];

					order[i] = order[j];
					order[j] = t;
				}
			}
		}
		fputc('{', out);
		for (i = 0; i < p->count; i++) {
			pl_t key = { .type = PL_STRING, .bytes = (uint8_t *)p->keys[order[i]],
				.len = strlen(p->keys[order[i]]) };

			if (i > 0) {
				fputc(',', out);
			}
			dump(&key, out);
			fputc(':', out);
			dump(p->items[order[i]], out);
		}
		fputc('}', out);
		free(order);
		break;
	}
}

static pl_t *
sarr(const char *s)
{
	pl_t *a = pl_array();

	pl_array_append(a, pl_string(s));
	return a;
}

static void
put_be(uint8_t *p, uint64_t v, unsigned n)
{
	unsigned i;

	for (i = 0; i < n; i++) {
		p[i] = (uint8_t)(v >> (8 * (n - 1 - i)));
	}
}

static uint8_t *
shared_data_plist(size_t refs, size_t size, size_t *len)
{
	size_t data = 8, array = data + 6 + size, table = array + 6 + 4 * refs, i;
	uint8_t *b, *p;

	*len = table + 8 + 32;
	b = calloc(1, *len);
	memcpy(b, "bplist00", 8);
	p = b + data;
	*p++ = 0x4F;
	*p++ = 0x12;
	put_be(p, size, 4);
	memset(p + 4, 'A', size);
	p = b + array;
	*p++ = 0xAF;
	*p++ = 0x12;
	put_be(p, refs, 4);
	p += 4;
	for (i = 0; i < refs; i++, p += 4) {
		put_be(p, 1, 4);
	}
	put_be(p, array, 4);
	put_be(p + 4, data, 4);
	p += 8 + 6;
	*p++ = 4;
	*p++ = 4;
	put_be(p, 2, 8);
	put_be(p + 8, 0, 8);
	put_be(p + 16, table, 8);
	return b;
}

static uint8_t *
many_keys_plist(size_t n, bool dup, size_t *len)
{
	size_t nobj = n + 2, table, i;
	uint8_t *b, *p;
	size_t *off = calloc(nobj, sizeof(*off));
	char key[32];

	*len = 8 + 6 + 8 * n + 9 * n + 2 + 4 * nobj + 32;
	b = calloc(1, *len);
	memcpy(b, "bplist00", 8);
	p = b + 8;
	off[0] = 8;
	*p++ = 0xDF;
	*p++ = 0x12;
	put_be(p, n, 4);
	p += 4;
	for (i = 0; i < n; i++, p += 4) {
		put_be(p, i + 1, 4);
	}
	for (i = 0; i < n; i++, p += 4) {
		put_be(p, n + 1, 4);
	}
	for (i = 0; i < n; i++) {
		off[i + 1] = (size_t)(p - b);
		*p++ = 0x58;
		snprintf(key, sizeof(key), "k%07zu", dup && i == n - 1 ? (size_t)0 : i);
		memcpy(p, key, 8);
		p += 8;
	}
	off[n + 1] = (size_t)(p - b);
	*p++ = 0x10;
	*p++ = 0;
	table = (size_t)(p - b);
	for (i = 0; i < nobj; i++, p += 4) {
		put_be(p, off[i], 4);
	}
	p += 6;
	*p++ = 4;
	*p++ = 4;
	put_be(p, nobj, 8);
	put_be(p + 8, 0, 8);
	put_be(p + 16, table, 8);
	free(off);
	return b;
}

static void
test_plist_limits(void)
{
	struct timespec t0, t1;
	uint8_t *buf;
	size_t len;
	pl_t *p, *c;

	buf = many_keys_plist(60000, false, &len);
	clock_gettime(CLOCK_MONOTONIC, &t0);
	p = pl_bplist_read(buf, len);
	c = pl_copy(p);
	clock_gettime(CLOCK_MONOTONIC, &t1);
	CHECK(p != NULL && p->count == 60000 && pl_dict_get(p, "k0059999") != NULL);
	CHECK(c != NULL && c->count == 60000 && strcmp(c->keys[59999], "k0059999") == 0);
	CHECK(t1.tv_sec - t0.tv_sec < 2);
	pl_free(c);
	pl_free(p);
	free(buf);
	buf = many_keys_plist(60000, true, &len);
	CHECK(pl_bplist_read(buf, len) == NULL);
	free(buf);
	buf = many_keys_plist(2, true, &len);
	CHECK(pl_bplist_read(buf, len) == NULL);
	free(buf);

	buf = shared_data_plist(16, 4096, &len);
	p = pl_bplist_read(buf, len);
	CHECK(p != NULL && p->count == 16 && pl_is(p->items[15], PL_DATA) && p->items[15]->len == 4096);
	pl_free(p);
	free(buf);
	buf = shared_data_plist(20000, 4096, &len);
	CHECK(pl_bplist_read(buf, len) == NULL);
	free(buf);
	buf = shared_data_plist(199998, 16384, &len);
	CHECK(len < 1024 * 1024 && pl_bplist_read(buf, len) == NULL);
	free(buf);
}

static void
test_plist(void)
{
	pl_t *p = pl_dict(), *a = pl_array(), *b, *big;
	uint8_t *out, *mut;
	size_t len, i, k;
	char key[32];
	uint8_t bytes[300];

	for (i = 0; i < sizeof(bytes); i++) {
		bytes[i] = (uint8_t)i;
	}
	pl_dict_set(p, "ascii", pl_string("hello"));
	pl_dict_set(p, "long", pl_string("a string that is longer than fifteen bytes"));
	pl_dict_set(p, "utf8", pl_string("caf\xc3\xa9 \xf0\x9f\x98\x80 \xe2\x82\xac"));
	pl_dict_set(p, "empty", pl_string(""));
	pl_dict_set(p, "data", pl_data(bytes, sizeof(bytes)));
	pl_dict_set(p, "edata", pl_data(NULL, 0));
	pl_array_append(a, pl_int(0));
	pl_array_append(a, pl_int(255));
	pl_array_append(a, pl_int(256));
	pl_array_append(a, pl_int(65536));
	pl_array_append(a, pl_int(4294967295LL));
	pl_array_append(a, pl_int(4294967296LL));
	pl_array_append(a, pl_int(-2));
	pl_array_append(a, pl_int(INT64_MIN));
	pl_array_append(a, pl_bool(true));
	pl_array_append(a, pl_bool(false));
	pl_dict_set(p, "nums", a);
	big = pl_dict();
	for (k = 0; k < 400; k++) {
		snprintf(key, sizeof(key), "k%zu", k);
		pl_dict_set(big, key, sarr(key));
	}
	pl_dict_set(p, "big", big);
	CHECK(pl_bplist_write(p, &out, &len) == 0);
	b = pl_bplist_read(out, len);
	CHECK(b != NULL && pl_equal(p, b));
	pl_free(b);

	CHECK(pl_bplist_read(out, len - 1) == NULL);
	CHECK(pl_bplist_read(out, 20) == NULL);
	mut = malloc(len);
	srand(1);
	for (i = 0; i < 20000; i++) {
		memcpy(mut, out, len);
		for (k = 0; k < 1 + (size_t)(rand() % 4); k++) {
			mut[(size_t)rand() % len] = (uint8_t)rand();
		}
		pl_free(pl_bplist_read(mut, len));
	}
	free(mut);
	free(out);

	{
		uint8_t raw[512];
		size_t n = 8, off[64], k, depth = 40;
		pl_t *r;

		memcpy(raw, "bplist00", 8);
		for (k = 0; k < depth; k++) {
			off[k] = n;
			raw[n++] = 0xA2;
			raw[n++] = (uint8_t)(k + 1);
			raw[n++] = (uint8_t)(k + 1);
		}
		off[depth] = n;
		raw[n++] = 0xA0;
		k = n;
		for (size_t j = 0; j <= depth; j++) {
			raw[n++] = (uint8_t)off[j];
		}
		memset(raw + n, 0, 32);
		raw[n + 6] = 1;
		raw[n + 7] = 1;
		raw[n + 15] = (uint8_t)(depth + 1);
		raw[n + 31] = (uint8_t)k;
		r = pl_bplist_read(raw, n + 32);
		CHECK(r == NULL);
		pl_free(r);
		raw[n + 15] = 1;
		raw[9] = 0;
		raw[10] = 0;
		raw[n + 31] = (uint8_t)k;
		CHECK(pl_bplist_read(raw, n + 32) == NULL);
	}
	pl_free(p);
}

static void
hex(const uint8_t *p, size_t n, char *out)
{
	size_t i;

	for (i = 0; i < n; i++) {
		sprintf(out + 2 * i, "%02x", p[i]);
	}
}

static void
test_pbkdf2(void)
{
	uint8_t dk[64], *shd;
	char h[129];
	size_t len;
	pl_t *top;
	const pl_t *in;

	CHECK(CCKeyDerivationPBKDF(kCCPBKDF2, "password", 8, (const uint8_t *)"salt", 4,
	    kCCPRFHmacAlgSHA512, 1, dk, 64) == kCCSuccess);
	hex(dk, 64, h);
	CHECK(strcmp(h, "867f70cf1ade02cff3752599a3a53dc4af34c7a669815ae5d513554e1c8cf252"
	    "c02d470a285a0501bad999bfe943c08f050235d7d68b1da55e63f73b60a57fce") == 0);
	CHECK(CCKeyDerivationPBKDF(kCCPBKDF2, "password", 8, (const uint8_t *)"salt", 4,
	    kCCPRFHmacAlgSHA512, 4096, dk, 64) == kCCSuccess);
	hex(dk, 64, h);
	CHECK(strcmp(h, "d197b1b33db0143e018b12f3d1d1479e6cdebdcc97c5c0f87f6902e072f457b5"
	    "143f30602641b3d55cd335988cb36b84376060ecd532e039b742a239434af2d5") == 0);

	CHECK(shadow_make("s3cret", 6, 1000, &shd, &len) == 0);
	top = pl_bplist_read(shd, len);
	in = pl_dict_get(top, "SALTED-SHA512-PBKDF2");
	CHECK(in != NULL && in->count == 3);
	CHECK(pl_dict_get(in, "entropy") != NULL && pl_dict_get(in, "entropy")->len == 128);
	CHECK(pl_dict_get(in, "salt") != NULL && pl_dict_get(in, "salt")->len == 32);
	CHECK(pl_dict_get(in, "iterations") != NULL && pl_dict_get(in, "iterations")->i == 1000);
	pl_free(top);
	CHECK(shadow_verify(shd, len, "s3cret", 6) == 1);
	CHECK(shadow_verify(shd, len, "s3cres", 6) == 0);
	CHECK(shadow_verify(shd, len, "s3cret!", 7) == 0);
	CHECK(shadow_verify(shd, len, "", 0) == 0);
	CHECK(shadow_verify(shd, len - 3, "s3cret", 6) == -1);
	CHECK(shadow_verify((const uint8_t *)"junk", 4, "s3cret", 6) == -1);
	free(shd);
	CHECK(od_consttime_equal((const uint8_t *)"abc", (const uint8_t *)"abc", 3));
	CHECK(!od_consttime_equal((const uint8_t *)"abc", (const uint8_t *)"abd", 3));
}

struct reply {
	uint64_t error;
	bool complete;
	pl_t *plist;
};

struct capture {
	struct reply r[64];
	size_t n;
};

static void
capture_send(void *ctx, uint64_t error, bool complete, const pl_t *reply)
{
	struct capture *c = ctx;
	uint8_t *data;
	size_t len;

	if (c->n == 64) {
		abort();
	}
	c->r[c->n].error = error;
	c->r[c->n].complete = complete;
	if (pl_bplist_write(reply, &data, &len) == 0) {
		c->r[c->n].plist = pl_bplist_read(data, len);
		free(data);
	}
	c->n++;
}

static void
capture_free(struct capture *c)
{
	size_t i;

	for (i = 0; i < c->n; i++) {
		pl_free(c->r[i].plist);
	}
	c->n = 0;
}

static const pl_t *
result(const struct reply *r, size_t i)
{
	const pl_t *slot = pl_array_get(pl_dict_get(r->plist, "results"), i);

	return pl_array_get(slot, 0);
}

static void
call(struct od *od, uid_t euid, void *peer, const uint8_t *node, struct capture *cap,
    const char *fn, size_t n, ...)
{
	static const uint8_t zero[16];
	struct od_caller caller = { euid, 4242, peer };
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
	pl_bplist_write(req, &data, &len);
	pl_free(req);
	capture_free(cap);
	od_api(od, &caller, zero, node != NULL ? node : zero, data, len, capture_send, cap);
	free(data);
}

static bool
open_node(struct od *od, uid_t euid, void *peer, const char *name, uint8_t uu[16])
{
	struct capture cap = { .n = 0 };
	const pl_t *v;
	bool ok;

	call(od, euid, peer, NULL, &cap, "ODNodeCreateWithName", 1, pl_string(name));
	v = cap.n == 1 ? result(&cap.r[0], 0) : NULL;
	ok = cap.n == 1 && cap.r[0].error == 0 && cap.r[0].complete && pl_is(v, PL_DATA) && v->len == 16;
	if (ok) {
		memcpy(uu, v->bytes, 16);
	}
	capture_free(&cap);
	return ok;
}

static pl_t *
users_type(void)
{
	return pl_string(OD_RECSTD "Users");
}

static void
setup_dir(char *dir, size_t size, struct od *od)
{
	char path[1200];
	FILE *f;
	const char *tmp = getenv("TMPDIR");

	snprintf(dir, size, "%s/odtest.XXXXXX", tmp != NULL ? tmp : "/tmp");
	if (mkdtemp(dir) == NULL) {
		abort();
	}
	memset(od, 0, sizeof(*od));
	snprintf(path, sizeof(path), "%s/shells", dir);
	f = fopen(path, "w");
	fputs("# shells\n/bin/sh\n/bin/zsh\n", f);
	fclose(f);
	od->shells_path = strdup(path);
	snprintf(path, sizeof(path), "%s/passwd", dir);
	f = fopen(path, "w");
	fputs("# users\nroot:*:0:0:System Administrator:/var/root:/bin/sh\n", f);
	fclose(f);
	od->passwd_path = strdup(path);
	snprintf(path, sizeof(path), "%s/master.passwd", dir);
	od->master_passwd_path = strdup(path);
	snprintf(path, sizeof(path), "%s/group", dir);
	f = fopen(path, "w");
	fputs("wheel:*:0:root\n", f);
	fclose(f);
	od->group_path = strdup(path);
	od->iterations = 1000;
	od->log = quiet_log;
	od->now = test_now;
	od->changed = test_changed;
	snprintf(path, sizeof(path), "%s/node", dir);
	if (od_init(od, path) != 0) {
		abort();
	}
}

static void
teardown(struct od *od, const char *dir)
{
	char cmd[128];

	free((char *)od->shells_path);
	free((char *)od->passwd_path);
	free((char *)od->master_passwd_path);
	free((char *)od->group_path);
	od_free(od);
	snprintf(cmd, sizeof(cmd), "rm -rf '%s'", dir);
	if (system(cmd) != 0) {
		fprintf(stderr, "cannot remove %s\n", dir);
	}
}

static void
put_record(struct od *od, enum rtype t, pl_t *rec)
{
	CHECK(store_write(&od->store, t, rec, NULL) == 0);
	pl_free(rec);
}

static pl_t *
make_user(const char *name, const char *uid, const char *gid, const char *guid)
{
	pl_t *r = pl_dict();

	pl_dict_set(r, "name", sarr(name));
	pl_dict_set(r, "uid", sarr(uid));
	pl_dict_set(r, "gid", sarr(gid));
	pl_dict_set(r, "home", sarr("/Users/x"));
	pl_dict_set(r, "shell", sarr("/bin/sh"));
	pl_dict_set(r, "realname", sarr("Some One"));
	pl_dict_set(r, "passwd", sarr("*"));
	if (guid != NULL) {
		pl_dict_set(r, "generateduid", sarr(guid));
	}
	return r;
}

static pl_t *
make_group(const char *name, const char *gid, const char *guid, const char *member)
{
	pl_t *r = pl_dict();

	pl_dict_set(r, "name", sarr(name));
	pl_dict_set(r, "gid", sarr(gid));
	if (guid != NULL) {
		pl_dict_set(r, "generateduid", sarr(guid));
	}
	if (member != NULL) {
		pl_dict_set(r, "users", sarr(member));
	}
	return r;
}

static void
seed(struct od *od)
{
	pl_t *g;

	put_record(od, RT_USERS, make_user("root", "0", "0", "FFFFEEEE-DDDD-CCCC-BBBB-AAAA00000000"));
	put_record(od, RT_USERS, make_user("pie", "501", "20", "11111111-2222-3333-4444-555555555555"));
	put_record(od, RT_USERS, make_user("bob", "502", "20", NULL));
	put_record(od, RT_USERS, make_user("nobody", "-2", "-2", "FFFFEEEE-DDDD-CCCC-BBBB-AAAAFFFFFFFE"));
	put_record(od, RT_GROUPS, make_group("staff", "20", "ABCDEFAB-CDEF-ABCD-EFAB-CDEF00000014", NULL));
	put_record(od, RT_GROUPS, make_group("admin", "80", "ABCDEFAB-CDEF-ABCD-EFAB-CDEF00000050", "pie"));
	put_record(od, RT_GROUPS, make_group("wheel", "0", NULL, "root"));
	g = make_group("devs", "600", "AAAAAAAA-0000-0000-0000-000000000600", NULL);
	pl_dict_set(g, "groupmembers", sarr("11111111-2222-3333-4444-555555555555"));
	put_record(od, RT_GROUPS, g);
	g = make_group("outer", "601", NULL, NULL);
	pl_dict_set(g, "nestedgroups", sarr("aaaaaaaa-0000-0000-0000-000000000600"));
	put_record(od, RT_GROUPS, g);
	put_record(od, RT_GROUPS, make_group("com.apple.access_ssh", "399", NULL, "bob"));
}

static void
test_store(void)
{
	char dir[1024], path[1200];
	struct od od;
	struct stat st;
	pl_t *r;
	FILE *f;

	setup_dir(dir, sizeof(dir), &od);
	seed(&od);
	store_refresh(&od.store, RT_USERS);
	CHECK(store_count(&od.store, RT_USERS) == 4);
	CHECK(store_find(&od.store, RT_USERS, "pie") != NULL);
	CHECK(store_find(&od.store, RT_USERS, "nope") == NULL);
	CHECK(store_find_id(&od.store, RT_USERS, "uid", 0xFFFFFFFEu) != NULL);
	snprintf(path, sizeof(path), "%s/node/users/pie.plist", dir);
	CHECK(stat(path, &st) == 0 && (st.st_mode & 0777) == 0600);
	snprintf(path, sizeof(path), "%s/node/users", dir);
	CHECK(stat(path, &st) == 0 && (st.st_mode & 0777) == 0700);

	r = pl_copy(store_find(&od.store, RT_USERS, "bob"));
	pl_dict_set(r, "name", sarr("robert"));
	CHECK(store_write(&od.store, RT_USERS, r, "bob") == 0);
	pl_free(r);
	CHECK(store_find(&od.store, RT_USERS, "bob") == NULL);
	CHECK(store_find(&od.store, RT_USERS, "robert") != NULL);
	snprintf(path, sizeof(path), "%s/node/users/bob.plist", dir);
	CHECK(access(path, F_OK) != 0);

	snprintf(path, sizeof(path), "%s/node/users/junk.plist", dir);
	f = fopen(path, "w");
	fputs("not a plist", f);
	fclose(f);
	snprintf(path, sizeof(path), "%s/node/users/.robert.tmp", dir);
	f = fopen(path, "w");
	fclose(f);
	store_refresh(&od.store, RT_USERS);
	CHECK(store_count(&od.store, RT_USERS) == 5);
	CHECK(store_find(&od.store, RT_USERS, "junk") == NULL);

	r = make_user("eve", "700", "20", NULL);
	{
		uint8_t *d;
		size_t len;

		pl_bplist_write(r, &d, &len);
		snprintf(path, sizeof(path), "%s/node/users/eve.plist", dir);
		write_file(path, d, len);
		free(d);
	}
	pl_free(r);
	store_refresh(&od.store, RT_USERS);
	CHECK(store_find(&od.store, RT_USERS, "eve") != NULL);
	CHECK(store_delete(&od.store, RT_USERS, "eve") == 0);
	CHECK(store_find(&od.store, RT_USERS, "eve") == NULL);

	snprintf(path, sizeof(path), "%s/node/users/.robert.tmp", dir);
	CHECK(access(path, F_OK) == 0);
	store_free(&od.store);
	snprintf(path, sizeof(path), "%s/node", dir);
	CHECK(store_init(&od.store, path) == 0);
	snprintf(path, sizeof(path), "%s/node/users/.robert.tmp", dir);
	CHECK(access(path, F_OK) != 0);
	store_refresh(&od.store, RT_USERS);
	CHECK(store_find(&od.store, RT_USERS, "robert") != NULL);

	CHECK(store_valid_name("pie"));
	CHECK(!store_valid_name("../x"));
	CHECK(!store_valid_name(".hidden"));
	CHECK(!store_valid_name("a/b"));
	CHECK(!store_valid_name(""));
	CHECK(!store_valid_name("a:b"));
	teardown(&od, dir);
}

static bool
has_attr(const pl_t *rec, const char *name)
{
	return pl_dict_get(rec, name) != NULL;
}

static uint64_t
change_password(struct od *od, uid_t euid, void *peer, const uint8_t *node, const char *user,
    const char *old, const char *new)
{
	struct capture cap = { .n = 0 };
	uint64_t e;

	call(od, euid, peer, node, &cap, "ODRecordChangePassword", 5, users_type(), pl_string(user), NULL,
	    old != NULL ? pl_string(old) : NULL, pl_string(new));
	CHECK(cap.n == 1 && cap.r[0].complete);
	e = cap.r[0].error;
	capture_free(&cap);
	return e;
}

static uint64_t
verify(struct od *od, uid_t euid, void *peer, const uint8_t *node, const char *user, const char *pw,
    int64_t *backoff)
{
	struct capture cap = { .n = 0 };
	const pl_t *info, *b;
	uint64_t e;

	call(od, euid, peer, node, &cap, "ODRecordVerifyPassword", 4, users_type(), pl_string(user), NULL,
	    pl_string(pw));
	CHECK(cap.n == 1 && cap.r[0].complete);
	e = cap.r[0].error;
	if (backoff != NULL) {
		info = result(&cap.r[0], 1);
		b = pl_dict_get(info, "BackOffSeconds");
		*backoff = pl_is(b, PL_INT) ? b->i : -1;
	}
	capture_free(&cap);
	return e;
}

static uint64_t
set_value(struct od *od, uid_t euid, void *peer, const uint8_t *node, const char *type,
    const char *name, const char *attr, pl_t *values)
{
	struct capture cap = { .n = 0 };
	uint64_t e;

	call(od, euid, peer, node, &cap, "ODRecordSetValue", 5, pl_string(type), pl_string(name), NULL,
	    pl_string(attr), values);
	CHECK(cap.n == 1 && cap.r[0].complete);
	e = cap.r[0].error;
	capture_free(&cap);
	return e;
}

static void
test_api(void)
{
	char dir[1024];
	struct od od;
	struct capture cap = { .n = 0 };
	uint8_t local[16], search[16], other[16], pnode[16], node2[16];
	int peer1, peer2;
	const pl_t *rec, *u;
	pl_t *want;
	int64_t backoff;
	int i;

	setup_dir(dir, sizeof(dir), &od);
	seed(&od);

	CHECK(open_node(&od, 0, &peer1, "/Local/Default", local));
	CHECK(open_node(&od, 0, &peer1, "/Search", search));
	call(&od, 0, &peer1, NULL, &cap, "ODNodeCreateWithName", 1, pl_string("/LDAPv3/x"));
	CHECK(cap.n == 1 && cap.r[0].error == ODE_NODE_UNKNOWN_NAME);

	call(&od, 501, &peer2, local, &cap, "ODNodeCopyUnreachableSubnodeNames", 0);
	CHECK(cap.n == 1 && cap.r[0].error == ODE_NODE_INVALID && cap.r[0].complete);

	call(&od, 0, &peer1, search, &cap, "ODQueryCreateWithNode", 6, users_type(),
	    pl_string(OD_STD "RecordName"), pl_int(OD_MATCH_EQUAL), sarr("pie"), NULL, pl_int(1));
	CHECK(cap.n == 2);
	CHECK(cap.r[0].error == 0 && !cap.r[0].complete &&
	    strcmp(pl_str(pl_dict_get(cap.r[0].plist, "funcname")), "ODQueryCreateWithNode") == 0);
	CHECK(pl_is(result(&cap.r[0], 0), PL_DATA));
	CHECK(cap.r[1].complete && strcmp(pl_str(pl_dict_get(cap.r[1].plist, "funcname")),
	    "ODQueryResponse") == 0);
	rec = result(&cap.r[1], 1);
	CHECK(rec != NULL && has_attr(rec, OD_STD "RecordName") && has_attr(rec, OD_STD "RecordType") &&
	    has_attr(rec, OD_STD "AppleMetaNodeLocation") && rec->count == 3);
	CHECK(strcmp(pl_str(pl_array_get(pl_dict_get(rec, OD_STD "AppleMetaNodeLocation"), 0)),
	    "/Local/Default") == 0);

	call(&od, 0, &peer1, search, &cap, "ODQueryCreateWithNode", 6, users_type(),
	    pl_string(OD_STD "RecordName"), pl_int(OD_MATCH_EQUAL), sarr("nobody-else"), NULL, pl_int(1));
	CHECK(cap.n == 1 && cap.r[0].complete && cap.r[0].error == 0);

	call(&od, 501, &peer2, NULL, &cap, "ODNodeCreateWithName", 1, pl_string("/Local/Default"));
	memcpy(other, result(&cap.r[0], 0)->bytes, 16);
	CHECK(change_password(&od, 0, &peer1, local, "pie", NULL, "piepass") == 0);
	CHECK(changes > 0);
	CHECK(verify(&od, 501, &peer2, other, "pie", "piepass", NULL) == 0);
	CHECK(verify(&od, 501, &peer2, other, "pie", "wrong", NULL) == ODE_CRED_INVALID);
	store_refresh(&od.store, RT_USERS);
	u = store_find(&od.store, RT_USERS, "pie");
	CHECK(strcmp(rec_first(u, "passwd"), OD_HIDDEN_PASSWORD) == 0);
	CHECK(strcmp(rec_first(u, "authentication_authority"),
	    ";ShadowHash;HASHLIST:<SALTED-SHA512-PBKDF2>") == 0);

	want = pl_array();
	pl_array_append(want, pl_string(OD_ATTR_ALL));
	pl_array_append(want, pl_string(OD_NATIVE "ShadowHashData"));
	call(&od, 501, &peer2, other, &cap, "ODQueryCreateWithNode", 6, users_type(),
	    pl_string(OD_STD "RecordName"), pl_int(OD_MATCH_EQUAL), sarr("pie"), pl_copy(want), pl_int(0));
	rec = result(&cap.r[1], 1);
	CHECK(rec != NULL && has_attr(rec, OD_STD "UniqueID") && has_attr(rec, OD_STD "AuthenticationAuthority"));
	CHECK(!has_attr(rec, OD_NATIVE "ShadowHashData"));
	call(&od, 0, &peer1, local, &cap, "ODQueryCreateWithNode", 6, users_type(),
	    pl_string(OD_STD "RecordName"), pl_int(OD_MATCH_EQUAL), sarr("pie"), want, pl_int(0));
	rec = result(&cap.r[1], 1);
	CHECK(rec != NULL && has_attr(rec, OD_NATIVE "ShadowHashData"));
	want = pl_array();
	pl_array_append(want, pl_string(OD_ATTR_ALL));
	call(&od, 0, &peer1, local, &cap, "ODQueryCreateWithNode", 6, users_type(),
	    pl_string(OD_STD "RecordName"), pl_int(OD_MATCH_EQUAL), sarr("pie"), want, pl_int(0));
	rec = result(&cap.r[1], 1);
	CHECK(rec != NULL && !has_attr(rec, OD_NATIVE "ShadowHashData"));

	call(&od, 501, &peer2, other, &cap, "ODQueryCreateWithNode", 6, users_type(),
	    pl_string(OD_NATIVE "ShadowHashData"), pl_int(OD_MATCH_BEGINS), sarr("b"), NULL, pl_int(0));
	CHECK(cap.n == 1 && cap.r[0].complete);

	call(&od, 501, &peer2, other, &cap, "ODQueryCreateWithNode", 6, NULL, NULL, pl_int(OD_MATCH_ANY),
	    NULL, NULL, pl_int(0));
	CHECK(cap.n == 11 && cap.r[10].complete && !cap.r[9].complete);

	call(&od, 501, &peer2, other, &cap, "ODQueryCreateWithNode", 6, users_type(),
	    pl_string(OD_STD "UniqueID"), pl_int(OD_MATCH_GREATER), sarr("500"), NULL, pl_int(0));
	CHECK(cap.n == 3);
	call(&od, 501, &peer2, other, &cap, "ODQueryCreateWithNode", 6, users_type(),
	    pl_string(OD_STD "RealName"), pl_int(OD_MATCH_CONTAINS | OD_MATCH_INSENSITIVE), sarr("SOME"),
	    NULL, pl_int(2));
	CHECK(cap.n == 3);
	call(&od, 501, &peer2, other, &cap, "ODQueryCreateWithNode", 6, users_type(), NULL,
	    pl_int(0x1234), NULL, NULL, pl_int(0));
	CHECK(cap.n == 1 && cap.r[0].error == ODE_QUERY_UNSUPPORTED_MATCH && cap.r[0].complete);

	CHECK(change_password(&od, 501, &peer2, other, "pie", "piepass", "newpie") == 0);
	CHECK(verify(&od, 501, &peer2, other, "pie", "newpie", NULL) == 0);
	CHECK(change_password(&od, 501, &peer2, other, "pie", NULL, "x") == ODE_CRED_NOT_AUTHORIZED);
	CHECK(change_password(&od, 502, &peer2, other, "pie", "newpie", "x") == ODE_CRED_NOT_AUTHORIZED);
	CHECK(change_password(&od, 501, &peer2, other, "pie", "bad", "x") == ODE_CRED_INVALID);
	CHECK(change_password(&od, 501, &peer2, other, "pie", "newpie", "") == ODE_PASSWORD_QUALITY);
	CHECK(change_password(&od, 0, &peer1, search, "pie", NULL, "x") == ODE_READ_ONLY_NODE);

	for (i = 0; i < 5; i++) {
		verify(&od, 501, &peer2, other, "pie", "bad", NULL);
	}
	CHECK(verify(&od, 501, &peer2, other, "pie", "newpie", &backoff) == ODE_ACCOUNT_TEMP_LOCKED);
	CHECK(backoff > 0 && backoff <= 4);
	call(&od, 501, &peer2, other, &cap, "ODRecordAuthenticationAllowed", 3, users_type(), pl_string("pie"),
	    NULL);
	CHECK(cap.n == 1 && cap.r[0].error == ODE_ACCOUNT_TEMP_LOCKED &&
	    pl_dict_get(result(&cap.r[0], 1), "BackOffSeconds") != NULL);
	fake_now += 120;
	CHECK(verify(&od, 501, &peer2, other, "pie", "newpie", NULL) == 0);
	call(&od, 501, &peer2, other, &cap, "ODRecordAuthenticationAllowed", 3, users_type(), pl_string("pie"),
	    NULL);
	CHECK(cap.n == 1 && cap.r[0].error == 0);

	call(&od, 502, &peer2, NULL, &cap, "ODNodeCreateWithName", 1, pl_string("/Local/Default"));
	memcpy(pnode, result(&cap.r[0], 0)->bytes, 16);
	call(&od, 502, &peer2, pnode, &cap, "ODNodeCreateRecord", 3, users_type(), pl_string("mallory"), NULL);
	CHECK(cap.n == 1 && cap.r[0].error == ODE_PERMISSION);
	call(&od, 502, &peer2, pnode, &cap, "ODNodeSetCredentials", 3, users_type(), pl_string("pie"),
	    pl_string("wrong"));
	CHECK(cap.n == 1 && cap.r[0].error == ODE_CRED_INVALID);
	call(&od, 502, &peer2, pnode, &cap, "ODNodeSetCredentials", 3, users_type(), pl_string("pie"),
	    pl_string("newpie"));
	CHECK(cap.n == 1 && cap.r[0].error == 0);
	{
		pl_t *attrs = pl_dict();

		pl_dict_set(attrs, OD_STD "UniqueID", sarr("503"));
		pl_dict_set(attrs, OD_STD "PrimaryGroupID", sarr("20"));
		pl_dict_set(attrs, OD_STD "RecordType", sarr("ignored"));
		call(&od, 502, &peer2, pnode, &cap, "ODNodeCreateRecord", 3, users_type(), pl_string("carol"),
		    attrs);
	}
	CHECK(cap.n == 1 && cap.r[0].error == 0);
	rec = result(&cap.r[0], 1);
	CHECK(rec != NULL && has_attr(rec, OD_STD "GeneratedUID") && has_attr(rec, OD_STD "UniqueID") &&
	    has_attr(rec, OD_STD "AppleMetaNodeLocation"));
	call(&od, 502, &peer2, pnode, &cap, "ODNodeCreateRecord", 3, users_type(), pl_string("carol"), NULL);
	CHECK(cap.n == 1 && cap.r[0].error == ODE_ALREADY_EXISTS);
	CHECK(change_password(&od, 502, &peer2, pnode, "carol", NULL, "carolpw") == 0);
	CHECK(verify(&od, 0, &peer1, local, "carol", "carolpw", NULL) == 0);

	call(&od, 502, &peer2, NULL, &cap, "ODNodeCreateWithName", 1, pl_string("/Local/Default"));
	memcpy(node2, result(&cap.r[0], 0)->bytes, 16);
	call(&od, 502, &peer2, node2, &cap, "ODNodeSetCredentials", 3, NULL, pl_string("carol"),
	    pl_string("carolpw"));
	CHECK(cap.n == 1 && cap.r[0].error == 0);
	CHECK(set_value(&od, 503, &peer2, node2, OD_RECSTD "Users", "bob", OD_STD "UserShell",
	    sarr("/bin/zsh")) == ODE_PERMISSION);
	CHECK(change_password(&od, 502, &peer2, node2, "carol", NULL, "carolpw2") == ODE_CRED_NOT_AUTHORIZED);
	CHECK(set_value(&od, 502, &peer2, node2, OD_RECSTD "Users", "carol", OD_STD "Password",
	    sarr("carolpw2")) == ODE_CRED_NOT_AUTHORIZED);
	CHECK(change_password(&od, 502, &peer2, node2, "carol", "carolpw", "carolpw2") == 0);

	CHECK(set_value(&od, 502, &peer2, other, OD_RECSTD "Users", "bob", OD_STD "UserShell",
	    sarr("/bin/zsh")) == 0);
	CHECK(set_value(&od, 502, &peer2, other, OD_RECSTD "Users", "bob", OD_STD "UserShell",
	    sarr("/tmp/evil")) == ODE_PERMISSION);
	CHECK(set_value(&od, 502, &peer2, other, OD_RECSTD "Users", "bob", OD_STD "UniqueID",
	    sarr("0")) == ODE_PERMISSION);
	{
		pl_t *svc = make_user("svc", "503", "20", NULL);

		pl_dict_set(svc, "shell", sarr("/usr/bin/false"));
		put_record(&od, RT_USERS, svc);
		svc = make_user("noshell", "504", "20", NULL);
		pl_dict_remove(svc, "shell");
		put_record(&od, RT_USERS, svc);
	}
	CHECK(set_value(&od, 503, &peer2, other, OD_RECSTD "Users", "svc", OD_STD "UserShell",
	    sarr("/bin/sh")) == ODE_PERMISSION);
	CHECK(set_value(&od, 504, &peer2, other, OD_RECSTD "Users", "noshell", OD_STD "UserShell",
	    sarr("/bin/sh")) == ODE_PERMISSION);
	store_refresh(&od.store, RT_USERS);
	CHECK(strcmp(rec_first(store_find(&od.store, RT_USERS, "svc"), "shell"), "/usr/bin/false") == 0);
	CHECK(set_value(&od, 503, &peer2, other, OD_RECSTD "Users", "svc", OD_STD "RealName",
	    sarr("Service")) == 0);
	CHECK(set_value(&od, 0, &peer1, local, OD_RECSTD "Users", "svc", OD_STD "UserShell",
	    sarr("/bin/sh")) == 0);
	CHECK(set_value(&od, 503, &peer2, other, OD_RECSTD "Users", "svc", OD_STD "UserShell",
	    sarr("/bin/zsh")) == 0);
	CHECK(set_value(&od, 503, &peer2, other, OD_RECSTD "Users", "svc", OD_STD "UserShell",
	    sarr("/usr/bin/false")) == ODE_PERMISSION);
	call(&od, 0, &peer1, local, &cap, "ODRecordDelete", 3, users_type(), pl_string("svc"), NULL);
	CHECK(cap.n == 1 && cap.r[0].error == 0);
	call(&od, 0, &peer1, local, &cap, "ODRecordDelete", 3, users_type(), pl_string("noshell"), NULL);
	CHECK(cap.n == 1 && cap.r[0].error == 0);
	CHECK(set_value(&od, 502, &peer2, other, OD_RECSTD "Users", "bob", OD_STD "RealName",
	    sarr("Bob B")) == 0);
	CHECK(set_value(&od, 502, &peer2, other, OD_RECSTD "Users", "pie", OD_STD "RealName",
	    sarr("Not Me")) == ODE_PERMISSION);
	CHECK(set_value(&od, 0, &peer1, local, OD_RECSTD "Users", "bob", OD_STD "UniqueID",
	    sarr("x1")) == ODE_ATTR_SCHEMA);
	CHECK(set_value(&od, 0, &peer1, local, OD_RECSTD "Users", "bob", OD_STD "NoSuchThing",
	    sarr("1")) == ODE_ATTR_UNKNOWN_TYPE);
	CHECK(set_value(&od, 0, &peer1, local, OD_RECSTD "Users", "bob", OD_STD "Comment",
	    pl_array()) == ODE_ATTR_UNKNOWN_TYPE);
	CHECK(set_value(&od, 0, &peer1, local, OD_RECSTD "Users", "bob", OD_STD "RecordName",
	    sarr("pie")) == ODE_ALREADY_EXISTS);
	CHECK(set_value(&od, 0, &peer1, local, OD_RECSTD "Users", "bob", OD_STD "RecordName",
	    sarr("bobby")) == 0);
	store_refresh(&od.store, RT_USERS);
	CHECK(store_find(&od.store, RT_USERS, "bobby") != NULL && store_find(&od.store, RT_USERS, "bob") == NULL);
	CHECK(set_value(&od, 0, &peer1, local, OD_RECSTD "Users", "bobby", OD_STD "Password",
	    sarr("bobpw")) == 0);
	CHECK(verify(&od, 0, &peer1, local, "bobby", "bobpw", NULL) == 0);
	CHECK(set_value(&od, 502, &peer2, other, OD_RECSTD "Users", "bobby", OD_STD "Password",
	    sarr("x")) == ODE_CRED_NOT_AUTHORIZED);

	call(&od, 0, &peer1, local, &cap, "ODRecordAddValue", 5, pl_string(OD_RECSTD "Groups"),
	    pl_string("admin"), NULL, pl_string(OD_STD "GroupMembership"), pl_string("bobby"));
	CHECK(cap.n == 1 && cap.r[0].error == 0);
	call(&od, 0, &peer1, local, &cap, "ODRecordRemoveValue", 5, pl_string(OD_RECSTD "Groups"),
	    pl_string("admin"), NULL, pl_string(OD_STD "GroupMembership"), pl_string("nobody-there"));
	CHECK(cap.n == 1 && cap.r[0].error == ODE_ATTR_VALUE_NOT_FOUND);
	call(&od, 0, &peer1, local, &cap, "ODRecordRemoveValue", 5, pl_string(OD_RECSTD "Groups"),
	    pl_string("admin"), NULL, pl_string(OD_STD "GroupMembership"), pl_string("bobby"));
	CHECK(cap.n == 1 && cap.r[0].error == 0);

	{
		pl_t *dis = sarr(";DisabledUser;;ShadowHash;HASHLIST:<SALTED-SHA512-PBKDF2>");

		CHECK(set_value(&od, 0, &peer1, local, OD_RECSTD "Users", "bobby",
		    OD_STD "AuthenticationAuthority", dis) == 0);
	}
	CHECK(verify(&od, 0, &peer1, local, "bobby", "bobpw", NULL) == ODE_ACCOUNT_DISABLED);
	call(&od, 0, &peer1, local, &cap, "ODRecordAuthenticationAllowed", 3, users_type(), pl_string("bobby"),
	    NULL);
	CHECK(cap.n == 1 && cap.r[0].error == ODE_ACCOUNT_DISABLED);

	call(&od, 502, &peer2, other, &cap, "ODRecordDelete", 3, users_type(), pl_string("carol"), NULL);
	CHECK(cap.n == 1 && cap.r[0].error == ODE_PERMISSION);
	call(&od, 0, &peer1, local, &cap, "ODRecordDelete", 3, users_type(), pl_string("carol"), NULL);
	CHECK(cap.n == 1 && cap.r[0].error == 0);
	call(&od, 0, &peer1, local, &cap, "ODRecordDelete", 3, users_type(), pl_string("carol"), NULL);
	CHECK(cap.n == 1 && cap.r[0].error == ODE_NO_LONGER_EXISTS);

	call(&od, 0, &peer1, local, &cap, "ODNodeCustomCall", 2, pl_int(1), NULL);
	CHECK(cap.n == 1 && cap.r[0].error == ODE_NOT_SUPPORTED && cap.r[0].complete);
	call(&od, 0, &peer1, local, &cap, "ODRecordVerifyPasswordExtended", 0);
	CHECK(cap.n == 1 && cap.r[0].error == ODE_NOT_SUPPORTED && cap.r[0].complete);
	call(&od, 0, &peer1, local, &cap, "ODQuerySynchronize", 1, pl_data("0123456789abcdef", 16));
	CHECK(cap.n == 1 && cap.r[0].error == ODE_QUERY_INVALID);
	call(&od, 0, &peer1, local, &cap, "ODQueryCancel", 1, pl_data("0123456789abcdef", 16));
	CHECK(cap.n == 1 && cap.r[0].error == 0);
	{
		static const uint8_t sess[16] = { 1 };
		struct od_caller caller = { 0, 1, &peer1 };
		pl_t *req = pl_dict();
		uint8_t *data;
		size_t len;

		pl_dict_set(req, "funcname", pl_string("ODNodeCreateWithName"));
		pl_dict_set(req, "parameters", pl_array());
		pl_bplist_write(req, &data, &len);
		pl_free(req);
		capture_free(&cap);
		od_api(&od, &caller, sess, local, data, len, capture_send, &cap);
		CHECK(cap.n == 1 && cap.r[0].error == ODE_SESSION_INVALID);
		capture_free(&cap);
		od_api(&od, &caller, sess, local, (const uint8_t *)"garbage", 7, capture_send, &cap);
		CHECK(cap.n == 1 && cap.r[0].error == ODE_PARAMETER && cap.r[0].complete);
		free(data);
		data = shared_data_plist(199998, 16384, &len);
		capture_free(&cap);
		od_api(&od, &caller, (const uint8_t[16]){ 0 }, local, data, len, capture_send, &cap);
		CHECK(cap.n == 1 && cap.r[0].error == ODE_PARAMETER && cap.r[0].complete);
		free(data);
	}
	{
		char *big = malloc(1100001);

		memset(big, 'a', 1100000);
		big[1100000] = '\0';
		call(&od, 0, &peer1, local, &cap, "ODNodeCopySubnodeNames", 1, pl_string(big));
		CHECK(cap.n == 1 && cap.r[0].error == ODE_PARAMETER && cap.r[0].complete);
		big[1000] = '\0';
		call(&od, 0, &peer1, local, &cap, "ODNodeCopySubnodeNames", 1, pl_string(big));
		CHECK(cap.n == 1 && cap.r[0].error == 0 && cap.r[0].complete);
		free(big);
	}
	call(&od, 0, &peer1, local, &cap, "ODNodeRelease", 0);
	CHECK(cap.n == 1 && cap.r[0].error == 0);
	call(&od, 0, &peer1, local, &cap, "ODNodeCopySubnodeNames", 0);
	CHECK(cap.n == 1 && cap.r[0].error == ODE_NODE_INVALID);
	od_peer_gone(&od, &peer2);
	call(&od, 501, &peer2, other, &cap, "ODNodeCopySubnodeNames", 0);
	CHECK(cap.n == 1 && cap.r[0].error == ODE_NODE_INVALID);
	capture_free(&cap);
	teardown(&od, dir);
}

static unsigned
lookup_count(const struct fails *t, const char *name)
{
	size_t i;

	for (i = 0; i < t->count; i++) {
		if (strcmp(t->e[i].name, name) == 0) {
			return t->e[i].count;
		}
	}
	return 0;
}

static bool
node_is_admin(struct od *od, uid_t euid, void *peer, const uint8_t *node, const char *name)
{
	struct capture cap = { .n = 0 };
	bool ok;

	call(od, euid, peer, node, &cap, "ODNodeCreateRecord", 3, users_type(), pl_string(name), NULL);
	ok = cap.n == 1 && cap.r[0].error == 0;
	capture_free(&cap);
	return ok;
}

static bool
set_creds(struct od *od, uid_t euid, void *peer, uint8_t node[16], const char *name, const char *pw)
{
	struct capture cap = { .n = 0 };
	bool ok;

	if (!open_node(od, euid, peer, "/Local/Default", node)) {
		return false;
	}
	call(od, euid, peer, node, &cap, "ODNodeSetCredentials", 3, users_type(), pl_string(name),
	    pl_string(pw));
	ok = cap.n == 1 && cap.r[0].error == 0;
	capture_free(&cap);
	return ok;
}

static void
test_creds(void)
{
	char dir[1024];
	struct od od;
	uint8_t local[16], n1[16];
	int peer1, peer2;

	setup_dir(dir, sizeof(dir), &od);
	seed(&od);
	CHECK(open_node(&od, 0, &peer1, "/Local/Default", local));
	CHECK(change_password(&od, 0, &peer1, local, "pie", NULL, "piepass") == 0);

	CHECK(set_creds(&od, 1000, &peer2, n1, "pie", "piepass"));
	CHECK(node_is_admin(&od, 1000, &peer2, n1, "made1"));
	CHECK(change_password(&od, 0, &peer1, local, "pie", NULL, "piepass") == 0);
	CHECK(!node_is_admin(&od, 1000, &peer2, n1, "made2"));
	CHECK(set_creds(&od, 1000, &peer2, n1, "pie", "piepass"));
	CHECK(node_is_admin(&od, 1000, &peer2, n1, "made2"));
	CHECK(change_password(&od, 501, &peer2, n1, "pie", "piepass", "piepass2") == 0);
	CHECK(!node_is_admin(&od, 1000, &peer2, n1, "made3"));

	CHECK(set_creds(&od, 1000, &peer2, n1, "pie", "piepass2"));
	CHECK(set_value(&od, 0, &peer1, local, OD_RECSTD "Users", "pie", OD_STD "AuthenticationAuthority",
	    sarr(";DisabledUser;;ShadowHash;HASHLIST:<SALTED-SHA512-PBKDF2>")) == 0);
	CHECK(!node_is_admin(&od, 1000, &peer2, n1, "made3"));
	CHECK(set_value(&od, 0, &peer1, local, OD_RECSTD "Users", "pie", OD_STD "AuthenticationAuthority",
	    sarr(";ShadowHash;HASHLIST:<SALTED-SHA512-PBKDF2>")) == 0);
	CHECK(!node_is_admin(&od, 1000, &peer2, n1, "made3"));

	CHECK(set_creds(&od, 1000, &peer2, n1, "pie", "piepass2"));
	CHECK(set_value(&od, 0, &peer1, local, OD_RECSTD "Users", "pie", OD_STD "Expire", sarr("999999")) == 0);
	CHECK(!node_is_admin(&od, 1000, &peer2, n1, "made3"));
	CHECK(!set_creds(&od, 1000, &peer2, n1, "pie", "piepass2"));
	CHECK(set_value(&od, 0, &peer1, local, OD_RECSTD "Users", "pie", OD_STD "Expire", sarr("2000000")) == 0);
	CHECK(set_creds(&od, 1000, &peer2, n1, "pie", "piepass2"));
	CHECK(node_is_admin(&od, 1000, &peer2, n1, "made3"));
	fake_now += 2000000;
	CHECK(!node_is_admin(&od, 1000, &peer2, n1, "made4"));
	fake_now -= 2000000;
	teardown(&od, dir);
}

static void
test_sizes(void)
{
	char dir[1024], *big;
	struct od od;
	uint8_t local[16], self[16];
	int peer1, peer2, i;
	pl_t *r, *many;

	setup_dir(dir, sizeof(dir), &od);
	seed(&od);
	big = malloc(1100001);
	memset(big, 'a', 1100000);
	big[1100000] = '\0';
	r = pl_copy(store_find(&od.store, RT_USERS, "bob"));
	pl_dict_set(r, "comment", sarr(big));
	errno = 0;
	CHECK(store_write(&od.store, RT_USERS, r, "bob") == -1 && errno == EFBIG);
	pl_free(r);
	CHECK(store_find(&od.store, RT_USERS, "bob") != NULL);

	CHECK(open_node(&od, 0, &peer1, "/Local/Default", local));
	big[600000] = '\0';
	CHECK(set_value(&od, 0, &peer1, local, OD_RECSTD "Users", "bob", OD_STD "Comment", sarr(big)) == 0);
	CHECK(set_value(&od, 0, &peer1, local, OD_RECSTD "Users", "bob", OD_STD "Note", sarr(big)) ==
	    ODE_ATTR_SCHEMA);
	store_refresh(&od.store, RT_USERS);
	CHECK(store_find(&od.store, RT_USERS, "bob") != NULL &&
	    rec_first(store_find(&od.store, RT_USERS, "bob"), "note") == NULL);

	CHECK(open_node(&od, 501, &peer2, "/Local/Default", self));
	big[1025] = '\0';
	CHECK(set_value(&od, 501, &peer2, self, OD_RECSTD "Users", "pie", OD_STD "RealName", sarr(big)) ==
	    ODE_ATTR_SCHEMA);
	big[1024] = '\0';
	CHECK(set_value(&od, 501, &peer2, self, OD_RECSTD "Users", "pie", OD_STD "RealName", sarr(big)) == 0);
	many = pl_array();
	for (i = 0; i < 17; i++) {
		pl_array_append(many, pl_string("x"));
	}
	CHECK(set_value(&od, 501, &peer2, self, OD_RECSTD "Users", "pie", OD_STD "Building",
	    pl_copy(many)) == ODE_ATTR_SCHEMA);
	pl_array_remove(many, 0);
	CHECK(set_value(&od, 501, &peer2, self, OD_RECSTD "Users", "pie", OD_STD "Building", many) == 0);
	free(big);
	teardown(&od, dir);
}

static void
test_backoff(void)
{
	char dir[1024], name[300];
	struct od od;
	struct capture cap = { .n = 0 };
	uint8_t local[16], n2[16];
	int peer1, peer2, i;
	int64_t backoff;

	setup_dir(dir, sizeof(dir), &od);
	seed(&od);
	CHECK(open_node(&od, 0, &peer1, "/Local/Default", local));
	CHECK(change_password(&od, 0, &peer1, local, "pie", NULL, "piepass") == 0);
	CHECK(open_node(&od, 1000, &peer2, "/Local/Default", n2));
	for (i = 0; i < 5; i++) {
		CHECK(verify(&od, 1000, &peer2, n2, "pie", "wrong", NULL) == ODE_CRED_INVALID);
	}
	CHECK(verify(&od, 1000, &peer2, n2, "pie", "wrong", &backoff) == ODE_ACCOUNT_TEMP_LOCKED);
	for (i = 0; i < 300; i++) {
		snprintf(name, sizeof(name), "nouser%d", i);
		call(&od, 1000, &peer2, n2, &cap, "ODNodeSetCredentials", 3, users_type(), pl_string(name),
		    pl_string("x"));
		CHECK(cap.n == 1 && cap.r[0].error == ODE_CRED_INVALID);
	}
	CHECK(verify(&od, 1000, &peer2, n2, "pie", "wrong", &backoff) == ODE_ACCOUNT_TEMP_LOCKED);
	CHECK(backoff > 0);
	CHECK(od.unknown.count <= 256 && od.known.count == 1);

	fake_now += 1000;
	for (i = 0; i < 256; i++) {
		snprintf(name, sizeof(name), "ghost%d", i);
		for (int j = 0; j < 5; j++) {
			backoff_failed(&od, name, false);
		}
	}
	CHECK(backoff_remaining(&od, "ghost0", false) > 0);
	for (i = 0; i < 6; i++) {
		backoff_failed(&od, "late", false);
	}
	CHECK(backoff_remaining(&od, "late", false) == 0);
	CHECK(backoff_remaining(&od, "ghost0", false) > 0 && backoff_remaining(&od, "ghost255", false) > 0);
	fake_now += 100;
	backoff_failed(&od, "later", false);
	CHECK(od.unknown.count == 256 && lookup_count(&od.unknown, "later") == 1);

	for (i = 0; i < 256; i++) {
		snprintf(name, sizeof(name), "user%d", i);
		for (int j = 0; j < 5; j++) {
			backoff_failed(&od, name, true);
		}
	}
	backoff_failed(&od, "user256", true);
	CHECK(od.known.count == 257);
	CHECK(backoff_remaining(&od, "user0", true) > 0 && backoff_remaining(&od, "user255", true) > 0);
	fake_now += 100;
	backoff_failed(&od, "user257", true);
	CHECK(od.known.count == 257 && lookup_count(&od.known, "user257") == 1 && lookup_count(&od.known, "user256") == 0);
	CHECK(lookup_count(&od.known, "user0") == 5);
	for (i = 0; i < 256; i++) {
		snprintf(name, sizeof(name), "once%d", i);
		backoff_failed(&od, name, true);
	}
	CHECK(lookup_count(&od.known, "user0") == 5 && lookup_count(&od.known, "user255") == 5);
	backoff_failed(&od, "user0", true);
	CHECK(backoff_remaining(&od, "user0", true) > 0);

	memset(name, 'n', OD_MAX_NAME + 1);
	name[OD_MAX_NAME + 1] = '\0';
	backoff_failed(&od, name, false);
	CHECK(lookup_count(&od.unknown, name) == 0);
	name[OD_MAX_NAME] = '\0';
	backoff_failed(&od, name, false);
	CHECK(lookup_count(&od.unknown, name) == 1);
	capture_free(&cap);
	teardown(&od, dir);
}

static pl_t *
req1(const char *key, pl_t *v)
{
	pl_t *d = pl_dict();

	pl_dict_set(d, key, v);
	return d;
}

static int64_t
err_of(const pl_t *r)
{
	const pl_t *e = pl_dict_get(r, "error");

	return pl_is(e, PL_INT) ? e->i : -1;
}

static void
test_libinfo(void)
{
	char dir[1024];
	struct od od;
	pl_t *req, *r;
	const pl_t *v;
	uint8_t uu[16];
	uint32_t id;

	setup_dir(dir, sizeof(dir), &od);
	seed(&od);

	req = req1("name", pl_string("pie"));
	r = od_libinfo(&od, "getpwnam", req);
	CHECK(err_of(r) == 0 && strcmp(pl_str(pl_dict_get(r, "pw_name")), "pie") == 0 &&
	    strcmp(pl_str(pl_dict_get(r, "pw_passwd")), "********") == 0 &&
	    pl_dict_get(r, "pw_uid")->i == 501 && pl_dict_get(r, "pw_gid")->i == 20 &&
	    strcmp(pl_str(pl_dict_get(r, "pw_gecos")), "Some One") == 0);
	pl_free(r);
	pl_free(req);
	req = req1("name", pl_string("ghost"));
	r = od_libinfo(&od, "getpwnam", req);
	CHECK(err_of(r) != 0);
	pl_free(r);
	pl_free(req);
	req = req1("uid", pl_int(4294967294LL));
	r = od_libinfo(&od, "getpwuid", req);
	CHECK(err_of(r) == 0 && strcmp(pl_str(pl_dict_get(r, "pw_name")), "nobody") == 0);
	pl_free(r);
	pl_free(req);
	uuid_parse_text("11111111-2222-3333-4444-555555555555", uu);
	req = req1("uuid", pl_data(uu, 16));
	r = od_libinfo(&od, "getpwuuid", req);
	CHECK(err_of(r) == 0 && strcmp(pl_str(pl_dict_get(r, "pw_name")), "pie") == 0);
	pl_free(r);
	pl_free(req);
	uuid_parse_text("FFFFEEEE-DDDD-CCCC-BBBB-AAAA000001F6", uu);
	req = req1("uuid", pl_data(uu, 16));
	r = od_libinfo(&od, "getpwuuid", req);
	CHECK(err_of(r) == 0 && strcmp(pl_str(pl_dict_get(r, "pw_name")), "bob") == 0);
	pl_free(r);
	pl_free(req);

	r = od_libinfo(&od, "getpwent", NULL);
	v = pl_dict_get(r, "result");
	CHECK(err_of(r) == 0 && pl_is(v, PL_ARRAY) && v->count == 3);
	pl_free(r);
	r = od_libinfo(&od, "getgrent", NULL);
	v = pl_dict_get(r, "result");
	CHECK(err_of(r) == 0 && pl_is(v, PL_ARRAY) && v->count == 5);
	pl_free(r);

	req = req1("name", pl_string("admin"));
	r = od_libinfo(&od, "getgrnam", req);
	CHECK(err_of(r) == 0 && pl_dict_get(r, "gr_gid")->i == 80 &&
	    strcmp(pl_str(pl_array_get(pl_dict_get(r, "gr_mem"), 0)), "pie") == 0);
	pl_free(r);
	pl_free(req);
	req = req1("gid", pl_int(20));
	r = od_libinfo(&od, "getgrgid", req);
	CHECK(err_of(r) == 0 && strcmp(pl_str(pl_dict_get(r, "gr_name")), "staff") == 0);
	pl_free(r);
	pl_free(req);

	req = req1("name", pl_string("pie"));
	pl_dict_set(req, "ngroups", pl_int(17));
	r = od_libinfo(&od, "getgrouplist", req);
	v = pl_dict_get(r, "groups");
	CHECK(err_of(r) == 0 && pl_dict_get(r, "count")->i == 4 && pl_is(v, PL_DATA) &&
	    v->len == 4 * sizeof(uint32_t));
	if (pl_is(v, PL_DATA) && v->len >= 4 * sizeof(uint32_t)) {
		uint32_t g[4];

		memcpy(g, v->bytes, sizeof(g));
		CHECK(g[0] == 20 && g[1] == 80 && g[2] == 600 && g[3] == 601);
	}
	pl_free(r);
	pl_free(req);
	req = req1("name", pl_string("ghost"));
	r = od_libinfo(&od, "getgrouplist", req);
	CHECK(pl_dict_get(r, "count")->i == 0);
	pl_free(r);
	pl_free(req);
	r = od_libinfo(&od, "getservbyname", NULL);
	CHECK(err_of(r) != 0);
	pl_free(r);
	r = od_libinfo(&od, "innetgr", NULL);
	CHECK(err_of(r) == 0 && pl_dict_get(r, "result")->i == 0);
	pl_free(r);

	req = pl_dict();
	id = 501;
	pl_dict_set(req, "type", pl_int(0));
	pl_dict_set(req, "requesting", pl_int(6));
	pl_dict_set(req, "identifier", pl_data(&id, 4));
	r = od_membership(&od, "mbr_identifier_translate", req);
	v = pl_dict_get(r, "identifier");
	uuid_parse_text("11111111-2222-3333-4444-555555555555", uu);
	CHECK(err_of(r) == 0 && pl_is(v, PL_DATA) && v->len == 16 && memcmp(v->bytes, uu, 16) == 0 &&
	    pl_dict_get(r, "rectype")->i == 1);
	pl_free(r);
	id = 12345;
	pl_dict_set(req, "identifier", pl_data(&id, 4));
	r = od_membership(&od, "mbr_identifier_translate", req);
	v = pl_dict_get(r, "identifier");
	uuid_parse_text("FFFFEEEE-DDDD-CCCC-BBBB-AAAA00003039", uu);
	CHECK(err_of(r) == 0 && pl_is(v, PL_DATA) && memcmp(v->bytes, uu, 16) == 0);
	pl_free(r);
	uuid_parse_text("11111111-2222-3333-4444-555555555555", uu);
	pl_dict_set(req, "type", pl_int(6));
	pl_dict_set(req, "requesting", pl_int(4));
	pl_dict_set(req, "identifier", pl_data(uu, 16));
	r = od_membership(&od, "mbr_identifier_translate", req);
	v = pl_dict_get(r, "identifier");
	CHECK(err_of(r) == 0 && pl_is(v, PL_DATA) && strcmp((const char *)v->bytes, "pie") == 0);
	pl_free(r);
	pl_dict_set(req, "requesting", pl_int(30));
	r = od_membership(&od, "mbr_identifier_translate", req);
	v = pl_dict_get(r, "identifier");
	CHECK(err_of(r) == 0 && pl_is(v, PL_DATA) && v->len == 4 && memcmp(v->bytes, &(uint32_t){ 501 }, 4) == 0);
	pl_free(r);
	pl_dict_set(req, "type", pl_int(5));
	pl_dict_set(req, "requesting", pl_int(6));
	pl_dict_set(req, "identifier", pl_data("admin", 5));
	r = od_membership(&od, "mbr_identifier_translate", req);
	v = pl_dict_get(r, "identifier");
	uuid_parse_text("ABCDEFAB-CDEF-ABCD-EFAB-CDEF00000050", uu);
	CHECK(err_of(r) == 0 && pl_is(v, PL_DATA) && memcmp(v->bytes, uu, 16) == 0 &&
	    pl_dict_get(r, "rectype")->i == 2);
	pl_free(r);
	pl_dict_set(req, "identifier", pl_data("nogroup", 7));
	r = od_membership(&od, "mbr_identifier_translate", req);
	CHECK(err_of(r) == ENOENT);
	pl_free(r);
	pl_free(req);

	req = pl_dict();
	uuid_parse_text("11111111-2222-3333-4444-555555555555", uu);
	pl_dict_set(req, "user_idtype", pl_int(6));
	pl_dict_set(req, "user_id", pl_data(uu, 16));
	pl_dict_set(req, "group_idtype", pl_int(1));
	id = 80;
	pl_dict_set(req, "group_id", pl_data(&id, 4));
	r = od_membership(&od, "mbr_check_membership", req);
	CHECK(err_of(r) == 0 && pl_dict_get(r, "ismember")->i == 1);
	pl_free(r);
	id = 601;
	pl_dict_set(req, "group_id", pl_data(&id, 4));
	r = od_membership(&od, "mbr_check_membership", req);
	CHECK(err_of(r) == 0 && pl_dict_get(r, "ismember")->i == 1);
	pl_free(r);
	id = 0;
	pl_dict_set(req, "group_id", pl_data(&id, 4));
	r = od_membership(&od, "mbr_check_membership", req);
	CHECK(err_of(r) == 0 && pl_dict_get(r, "ismember")->i == 0);
	pl_free(r);
	id = 4444;
	pl_dict_set(req, "group_id", pl_data(&id, 4));
	r = od_membership(&od, "mbr_check_membership", req);
	CHECK(err_of(r) == 0 && pl_dict_get(r, "ismember")->i == 0);
	pl_free(r);
	pl_dict_set(req, "group_idtype", pl_int(5));
	pl_dict_set(req, "group_id", pl_data("staff", 5));
	r = od_membership(&od, "mbr_check_membership", req);
	CHECK(err_of(r) == 0 && pl_dict_get(r, "ismember")->i == 1);
	pl_free(r);
	uuid_parse_text("FFFFEEEE-DDDD-CCCC-BBBB-AAAA000001F6", uu);
	pl_dict_set(req, "user_id", pl_data(uu, 16));
	pl_dict_set(req, "service", pl_string("ssh"));
	r = od_membership(&od, "mbr_check_service_membership", req);
	CHECK(err_of(r) == 0 && pl_dict_get(r, "ismember")->i == 1);
	pl_free(r);
	pl_dict_set(req, "service", pl_string("ftp"));
	r = od_membership(&od, "mbr_check_service_membership", req);
	CHECK(err_of(r) == ENOENT && pl_dict_get(r, "ismember")->i == 0);
	pl_free(r);
	pl_free(req);
	r = od_membership(&od, "mbr_cache_flush", NULL);
	CHECK(err_of(r) == 0);
	pl_free(r);
	teardown(&od, dir);
}

static void
ask(struct od *od, struct kauth_identity_extlookup *el, uint32_t flags, const char *name, char *out)
{
	el->el_seqno = 77;
	el->el_result = KAUTH_EXTLOOKUP_INPROG;
	el->el_flags = flags;
	od_resolve(od, el, name, out, 256);
}

static bool
guid_is(const guid_t *g, const char *text)
{
	uint8_t uu[16];

	return uuid_parse_text(text, uu) && memcmp(g->g_guid, uu, 16) == 0;
}

static bool
ttls_set(const struct kauth_identity_extlookup *el)
{
	return el->el_uguid_valid == OD_RESOLVER_TTL && el->el_usid_valid == OD_RESOLVER_TTL &&
	    el->el_gguid_valid == OD_RESOLVER_TTL && el->el_gsid_valid == OD_RESOLVER_TTL &&
	    el->el_member_valid == OD_RESOLVER_TTL;
}

static bool
ismember(struct od *od, uid_t uid, gid_t gid)
{
	struct kauth_identity_extlookup el;
	uint32_t want = KAUTH_EXTLOOKUP_VALID_UID | KAUTH_EXTLOOKUP_VALID_GID |
	    KAUTH_EXTLOOKUP_VALID_MEMBERSHIP;

	memset(&el, 0, sizeof(el));
	el.el_uid = uid;
	el.el_gid = gid;
	ask(od, &el, KAUTH_EXTLOOKUP_VALID_UID | KAUTH_EXTLOOKUP_VALID_GID | KAUTH_EXTLOOKUP_WANT_MEMBERSHIP,
	    NULL, NULL);
	CHECK(el.el_result == KAUTH_EXTLOOKUP_SUCCESS && (el.el_flags & want) == want &&
	    el.el_uid == uid && el.el_gid == gid && el.el_member_valid == OD_RESOLVER_TTL);
	return (el.el_flags & KAUTH_EXTLOOKUP_ISMEMBER) != 0;
}

#define ALL_WANTS (KAUTH_EXTLOOKUP_WANT_UID | KAUTH_EXTLOOKUP_WANT_GID | KAUTH_EXTLOOKUP_WANT_UGUID | \
	KAUTH_EXTLOOKUP_WANT_GGUID | KAUTH_EXTLOOKUP_WANT_USID | KAUTH_EXTLOOKUP_WANT_GSID)

static void
test_resolver(void)
{
	static const uint32_t names = KAUTH_EXTLOOKUP_VALID_PWNAM | KAUTH_EXTLOOKUP_VALID_GRNAM;
	char dir[1024], out[256], name[32];
	struct kauth_identity_extlookup el;
	struct od od, od2;
	uint8_t node[16];
	pl_t *u, *g;
	ntsid_t sid;
	size_t i;
	int n;

	setup_dir(dir, sizeof(dir), &od);
	seed(&od);
	u = make_user("ann", "503", "20", "33333333-0000-0000-0000-000000000503");
	pl_dict_set(u, "smb_sid", sarr("S-1-5-21-100-200-300-1503"));
	put_record(&od, RT_USERS, u);
	g = make_group("inner", "602", "44444444-0000-0000-0000-000000000602", "ann");
	pl_dict_set(g, "smb_sid", sarr("S-1-5-21-100-200-300-2602"));
	put_record(&od, RT_GROUPS, g);
	g = make_group("top", "603", NULL, NULL);
	pl_dict_set(g, "nestedgroups", sarr("44444444-0000-0000-0000-000000000602"));
	put_record(&od, RT_GROUPS, g);
	put_record(&od, RT_USERS, make_user("badsid", "504", "20", NULL));
	put_record(&od, RT_GROUPS, make_group("blank", "604", NULL, NULL));

	memset(&el, 0, sizeof(el));
	el.el_uid = 501;
	ask(&od, &el, KAUTH_EXTLOOKUP_VALID_UID | ALL_WANTS, NULL, out);
	CHECK(el.el_seqno == 77 && el.el_result == KAUTH_EXTLOOKUP_SUCCESS && ttls_set(&el));
	CHECK((el.el_flags & (KAUTH_EXTLOOKUP_VALID_UID | KAUTH_EXTLOOKUP_VALID_UGUID)) ==
	    (KAUTH_EXTLOOKUP_VALID_UID | KAUTH_EXTLOOKUP_VALID_UGUID) && el.el_uid == 501 &&
	    guid_is(&el.el_uguid, "11111111-2222-3333-4444-555555555555"));
	CHECK(!(el.el_flags & (KAUTH_EXTLOOKUP_VALID_GID | KAUTH_EXTLOOKUP_VALID_GGUID |
	    KAUTH_EXTLOOKUP_VALID_USID | KAUTH_EXTLOOKUP_VALID_GSID | names |
	    KAUTH_EXTLOOKUP_VALID_MEMBERSHIP)));
	CHECK((el.el_flags & ALL_WANTS) == ALL_WANTS);

	memset(&el, 0, sizeof(el));
	el.el_uid = 502;
	ask(&od, &el, KAUTH_EXTLOOKUP_VALID_UID | ALL_WANTS, NULL, out);
	CHECK((el.el_flags & KAUTH_EXTLOOKUP_VALID_UGUID) &&
	    guid_is(&el.el_uguid, "FFFFEEEE-DDDD-CCCC-BBBB-AAAA000001F6"));
	memset(&el, 0, sizeof(el));
	el.el_uid = 12345;
	ask(&od, &el, KAUTH_EXTLOOKUP_VALID_UID | ALL_WANTS, NULL, out);
	CHECK(el.el_result == KAUTH_EXTLOOKUP_SUCCESS && (el.el_flags & KAUTH_EXTLOOKUP_VALID_UID) &&
	    el.el_uid == 12345 && (el.el_flags & KAUTH_EXTLOOKUP_VALID_UGUID) &&
	    guid_is(&el.el_uguid, "FFFFEEEE-DDDD-CCCC-BBBB-AAAA00003039") &&
	    !(el.el_flags & KAUTH_EXTLOOKUP_VALID_USID));

	memset(&el, 0, sizeof(el));
	el.el_gid = 600;
	ask(&od, &el, KAUTH_EXTLOOKUP_VALID_GID | ALL_WANTS, NULL, out);
	CHECK((el.el_flags & (KAUTH_EXTLOOKUP_VALID_GID | KAUTH_EXTLOOKUP_VALID_GGUID)) ==
	    (KAUTH_EXTLOOKUP_VALID_GID | KAUTH_EXTLOOKUP_VALID_GGUID) && el.el_gid == 600 &&
	    guid_is(&el.el_gguid, "AAAAAAAA-0000-0000-0000-000000000600") &&
	    !(el.el_flags & (KAUTH_EXTLOOKUP_VALID_UID | KAUTH_EXTLOOKUP_VALID_UGUID)) && ttls_set(&el));
	memset(&el, 0, sizeof(el));
	el.el_gid = 601;
	ask(&od, &el, KAUTH_EXTLOOKUP_VALID_GID | ALL_WANTS, NULL, out);
	CHECK(guid_is(&el.el_gguid, "ABCDEFAB-CDEF-ABCD-EFAB-CDEF00000259"));

	memset(&el, 0, sizeof(el));
	uuid_parse_text("11111111-2222-3333-4444-555555555555", el.el_uguid.g_guid);
	el.el_gguid = el.el_uguid;
	ask(&od, &el, KAUTH_EXTLOOKUP_VALID_UGUID | KAUTH_EXTLOOKUP_VALID_GGUID | ALL_WANTS, NULL, out);
	CHECK(el.el_result == KAUTH_EXTLOOKUP_SUCCESS && (el.el_flags & KAUTH_EXTLOOKUP_VALID_UID) &&
	    el.el_uid == 501 && (el.el_flags & KAUTH_EXTLOOKUP_VALID_UGUID) &&
	    !(el.el_flags & (KAUTH_EXTLOOKUP_VALID_GID | KAUTH_EXTLOOKUP_VALID_GGUID)) && ttls_set(&el));
	memset(&el, 0, sizeof(el));
	uuid_parse_text("aaaaaaaa-0000-0000-0000-000000000600", el.el_uguid.g_guid);
	el.el_gguid = el.el_uguid;
	ask(&od, &el, KAUTH_EXTLOOKUP_VALID_UGUID | KAUTH_EXTLOOKUP_VALID_GGUID | ALL_WANTS, NULL, out);
	CHECK((el.el_flags & (KAUTH_EXTLOOKUP_VALID_GID | KAUTH_EXTLOOKUP_VALID_GGUID)) ==
	    (KAUTH_EXTLOOKUP_VALID_GID | KAUTH_EXTLOOKUP_VALID_GGUID) && el.el_gid == 600 &&
	    !(el.el_flags & (KAUTH_EXTLOOKUP_VALID_UID | KAUTH_EXTLOOKUP_VALID_UGUID)));
	memset(&el, 0, sizeof(el));
	uuid_parse_text("FFFFEEEE-DDDD-CCCC-BBBB-AAAA000001F5", el.el_uguid.g_guid);
	el.el_gguid = el.el_uguid;
	ask(&od, &el, KAUTH_EXTLOOKUP_VALID_UGUID | KAUTH_EXTLOOKUP_VALID_GGUID | ALL_WANTS, NULL, out);
	CHECK((el.el_flags & KAUTH_EXTLOOKUP_VALID_UID) && el.el_uid == 501 &&
	    guid_is(&el.el_uguid, "11111111-2222-3333-4444-555555555555"));
	memset(&el, 0, sizeof(el));
	uuid_parse_text("ABCDEFAB-CDEF-ABCD-EFAB-CDEF00000D05", el.el_uguid.g_guid);
	el.el_gguid = el.el_uguid;
	ask(&od, &el, KAUTH_EXTLOOKUP_VALID_UGUID | KAUTH_EXTLOOKUP_VALID_GGUID | ALL_WANTS, NULL, out);
	CHECK((el.el_flags & KAUTH_EXTLOOKUP_VALID_GID) && el.el_gid == 3333 &&
	    !(el.el_flags & KAUTH_EXTLOOKUP_VALID_UID) &&
	    guid_is(&el.el_gguid, "ABCDEFAB-CDEF-ABCD-EFAB-CDEF00000D05"));
	memset(&el, 0, sizeof(el));
	uuid_parse_text("FFFFEEEE-DDDD-CCCC-BBBB-AAAA000001F5", el.el_gguid.g_guid);
	ask(&od, &el, KAUTH_EXTLOOKUP_VALID_GGUID | ALL_WANTS, NULL, out);
	CHECK(el.el_result == KAUTH_EXTLOOKUP_SUCCESS &&
	    !(el.el_flags & (KAUTH_EXTLOOKUP_VALID_UID | KAUTH_EXTLOOKUP_VALID_GID)));
	memset(&el, 0, sizeof(el));
	uuid_parse_text("12345678-9abc-def0-1234-56789abcdef0", el.el_uguid.g_guid);
	el.el_gguid = el.el_uguid;
	ask(&od, &el, KAUTH_EXTLOOKUP_VALID_UGUID | KAUTH_EXTLOOKUP_VALID_GGUID | ALL_WANTS, NULL, out);
	CHECK(el.el_result == KAUTH_EXTLOOKUP_SUCCESS && !(el.el_flags & (KAUTH_EXTLOOKUP_VALID_UID |
	    KAUTH_EXTLOOKUP_VALID_GID | KAUTH_EXTLOOKUP_VALID_UGUID | KAUTH_EXTLOOKUP_VALID_GGUID)));

	memset(&el, 0, sizeof(el));
	el.el_uid = 503;
	ask(&od, &el, KAUTH_EXTLOOKUP_VALID_UID | ALL_WANTS, NULL, out);
	CHECK((el.el_flags & KAUTH_EXTLOOKUP_VALID_USID) && el.el_usid.sid_kind == 1 &&
	    el.el_usid.sid_authcount == 5 && el.el_usid.sid_authority[5] == 5 &&
	    el.el_usid.sid_authority[0] == 0 && el.el_usid.sid_authorities[0] == 21 &&
	    el.el_usid.sid_authorities[1] == 100 && el.el_usid.sid_authorities[4] == 1503);
	sid = el.el_usid;
	memset(&el, 0, sizeof(el));
	el.el_usid = sid;
	el.el_gsid = sid;
	ask(&od, &el, KAUTH_EXTLOOKUP_VALID_USID | KAUTH_EXTLOOKUP_VALID_GSID | ALL_WANTS, NULL, out);
	CHECK((el.el_flags & KAUTH_EXTLOOKUP_VALID_UID) && el.el_uid == 503 &&
	    (el.el_flags & KAUTH_EXTLOOKUP_VALID_USID) &&
	    guid_is(&el.el_uguid, "33333333-0000-0000-0000-000000000503") &&
	    !(el.el_flags & KAUTH_EXTLOOKUP_VALID_GID));
	memset(&el, 0, sizeof(el));
	el.el_gid = 602;
	ask(&od, &el, KAUTH_EXTLOOKUP_VALID_GID | ALL_WANTS, NULL, out);
	CHECK((el.el_flags & KAUTH_EXTLOOKUP_VALID_GSID) && el.el_gsid.sid_authorities[4] == 2602);
	sid = el.el_gsid;
	memset(&el, 0, sizeof(el));
	el.el_usid = sid;
	el.el_gsid = sid;
	ask(&od, &el, KAUTH_EXTLOOKUP_VALID_USID | KAUTH_EXTLOOKUP_VALID_GSID | ALL_WANTS, NULL, out);
	CHECK((el.el_flags & KAUTH_EXTLOOKUP_VALID_GID) && el.el_gid == 602 &&
	    !(el.el_flags & KAUTH_EXTLOOKUP_VALID_UID));
	sid.sid_authorities[4] = 9999;
	memset(&el, 0, sizeof(el));
	el.el_usid = sid;
	el.el_gsid = sid;
	ask(&od, &el, KAUTH_EXTLOOKUP_VALID_USID | KAUTH_EXTLOOKUP_VALID_GSID | ALL_WANTS, NULL, out);
	CHECK(el.el_result == KAUTH_EXTLOOKUP_SUCCESS &&
	    !(el.el_flags & (KAUTH_EXTLOOKUP_VALID_UID | KAUTH_EXTLOOKUP_VALID_GID)));
	{
		static const char *const bad[] = { "S-1-5-21-x", "S-256-5-1", "S-1-281474976710656-1",
			"S-1-5-4294967296", "S-1-5-1-2-3-4-5-6-7-8-9-10-11-12-13-14-15-16-17", "S-1--5",
			"s-1-5-1", "S-1-5-1-", "S-+1-5", "" };

		for (i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
			u = make_user("badsid", "504", "20", NULL);
			pl_dict_set(u, "smb_sid", sarr(bad[i]));
			put_record(&od, RT_USERS, u);
			memset(&el, 0, sizeof(el));
			el.el_uid = 504;
			ask(&od, &el, KAUTH_EXTLOOKUP_VALID_UID | ALL_WANTS, NULL, out);
			CHECK((el.el_flags & KAUTH_EXTLOOKUP_VALID_UID) &&
			    !(el.el_flags & KAUTH_EXTLOOKUP_VALID_USID));
		}
		u = make_user("badsid", "504", "20", NULL);
		pl_dict_set(u, "smb_sid",
		    sarr("S-1-281474976710655-1-2-3-4-5-6-7-8-9-10-11-12-13-14-15-4294967295"));
		put_record(&od, RT_USERS, u);
		memset(&el, 0, sizeof(el));
		el.el_uid = 504;
		ask(&od, &el, KAUTH_EXTLOOKUP_VALID_UID | ALL_WANTS, NULL, out);
		CHECK((el.el_flags & KAUTH_EXTLOOKUP_VALID_USID) && el.el_usid.sid_authcount == 16 &&
		    el.el_usid.sid_authority[0] == 0xff && el.el_usid.sid_authority[5] == 0xff &&
		    el.el_usid.sid_authorities[15] == 4294967295U);
	}

	memset(&el, 0, sizeof(el));
	ask(&od, &el, KAUTH_EXTLOOKUP_VALID_PWNAM | ALL_WANTS, "pie", out);
	CHECK(el.el_result == KAUTH_EXTLOOKUP_SUCCESS && (el.el_flags & KAUTH_EXTLOOKUP_VALID_UID) &&
	    el.el_uid == 501 && (el.el_flags & KAUTH_EXTLOOKUP_VALID_UGUID) && !(el.el_flags & names));
	memset(&el, 0, sizeof(el));
	ask(&od, &el, KAUTH_EXTLOOKUP_VALID_PWNAM | ALL_WANTS, "admin", out);
	CHECK(el.el_result == KAUTH_EXTLOOKUP_SUCCESS &&
	    !(el.el_flags & (KAUTH_EXTLOOKUP_VALID_UID | KAUTH_EXTLOOKUP_VALID_GID | names)));
	memset(&el, 0, sizeof(el));
	ask(&od, &el, KAUTH_EXTLOOKUP_VALID_GRNAM | ALL_WANTS, "admin", out);
	CHECK((el.el_flags & KAUTH_EXTLOOKUP_VALID_GID) && el.el_gid == 80 &&
	    guid_is(&el.el_gguid, "ABCDEFAB-CDEF-ABCD-EFAB-CDEF00000050") && !(el.el_flags & names));
	memset(&el, 0, sizeof(el));
	ask(&od, &el, KAUTH_EXTLOOKUP_VALID_PWNAM | ALL_WANTS, "ghost", out);
	CHECK(el.el_result == KAUTH_EXTLOOKUP_SUCCESS &&
	    !(el.el_flags & (KAUTH_EXTLOOKUP_VALID_UID | names)));
	memset(&el, 0, sizeof(el));
	ask(&od, &el, KAUTH_EXTLOOKUP_VALID_PWNAM | ALL_WANTS, "", out);
	CHECK(el.el_result == KAUTH_EXTLOOKUP_BADRQ);
	memset(&el, 0, sizeof(el));
	ask(&od, &el, ALL_WANTS, NULL, out);
	CHECK(el.el_result == KAUTH_EXTLOOKUP_BADRQ && el.el_seqno == 77 &&
	    !(el.el_flags & (KAUTH_EXTLOOKUP_VALID_UID | KAUTH_EXTLOOKUP_VALID_GID)));

	memset(&el, 0, sizeof(el));
	memset(out, 'x', sizeof(out));
	uuid_parse_text("11111111-2222-3333-4444-555555555555", el.el_uguid.g_guid);
	el.el_gguid = el.el_uguid;
	ask(&od, &el, KAUTH_EXTLOOKUP_VALID_UGUID | KAUTH_EXTLOOKUP_VALID_GGUID | ALL_WANTS |
	    KAUTH_EXTLOOKUP_WANT_PWNAM, NULL, out);
	CHECK((el.el_flags & KAUTH_EXTLOOKUP_VALID_PWNAM) && !(el.el_flags & KAUTH_EXTLOOKUP_VALID_GRNAM) &&
	    el.el_extend == (uint64_t)(uintptr_t)out && strcmp(out, "pie") == 0);
	memset(&el, 0, sizeof(el));
	uuid_parse_text("ABCDEFAB-CDEF-ABCD-EFAB-CDEF00000050", el.el_uguid.g_guid);
	el.el_gguid = el.el_uguid;
	ask(&od, &el, KAUTH_EXTLOOKUP_VALID_UGUID | KAUTH_EXTLOOKUP_VALID_GGUID | ALL_WANTS |
	    KAUTH_EXTLOOKUP_WANT_GRNAM, NULL, out);
	CHECK((el.el_flags & KAUTH_EXTLOOKUP_VALID_GRNAM) && !(el.el_flags & KAUTH_EXTLOOKUP_VALID_PWNAM) &&
	    el.el_extend == (uint64_t)(uintptr_t)out && strcmp(out, "admin") == 0);
	memset(&el, 0, sizeof(el));
	ask(&od, &el, KAUTH_EXTLOOKUP_VALID_UGUID | KAUTH_EXTLOOKUP_VALID_GGUID | ALL_WANTS |
	    KAUTH_EXTLOOKUP_WANT_PWNAM, NULL, out);
	CHECK(!(el.el_flags & names) && el.el_extend == 0);
	memset(&el, 0, sizeof(el));
	el.el_uid = 12345;
	ask(&od, &el, KAUTH_EXTLOOKUP_VALID_UID | ALL_WANTS | KAUTH_EXTLOOKUP_WANT_PWNAM, NULL, out);
	CHECK((el.el_flags & KAUTH_EXTLOOKUP_VALID_UID) && !(el.el_flags & names));

	CHECK(ismember(&od, 501, 80));
	CHECK(ismember(&od, 501, 600));
	CHECK(ismember(&od, 501, 601));
	CHECK(ismember(&od, 501, 20));
	CHECK(!ismember(&od, 501, 0));
	CHECK(!ismember(&od, 501, 4444));
	CHECK(ismember(&od, 501, 12));
	CHECK(ismember(&od, 503, 602));
	CHECK(ismember(&od, 503, 603));
	CHECK(!ismember(&od, 501, 603));
	CHECK(!ismember(&od, 502, 80));
	CHECK(ismember(&od, 502, 20));
	CHECK(ismember(&od, 502, 399));
	CHECK(!ismember(&od, 12345, 12));
	CHECK(!ismember(&od, 12345, 20));
	CHECK(ismember(&od, 0, 0));
	memset(&el, 0, sizeof(el));
	el.el_uid = 501;
	ask(&od, &el, KAUTH_EXTLOOKUP_VALID_UID | KAUTH_EXTLOOKUP_WANT_MEMBERSHIP, NULL, out);
	CHECK(el.el_result == KAUTH_EXTLOOKUP_SUCCESS && !(el.el_flags & KAUTH_EXTLOOKUP_VALID_MEMBERSHIP));

	memset(&el, 0, sizeof(el));
	el.el_uid = 501;
	ask(&od, &el, KAUTH_EXTLOOKUP_VALID_UID | ALL_WANTS | KAUTH_EXTLOOKUP_WANT_SUPGRPS, NULL, out);
	CHECK((el.el_flags & KAUTH_EXTLOOKUP_VALID_SUPGRPS) && el.el_sup_grp_cnt == 4 &&
	    el.el_sup_groups[0] == 20 && el.el_member_valid == OD_RESOLVER_TTL);
	{
		bool s80 = false, s600 = false, s601 = false;

		for (i = 0; i < el.el_sup_grp_cnt; i++) {
			s80 |= el.el_sup_groups[i] == 80;
			s600 |= el.el_sup_groups[i] == 600;
			s601 |= el.el_sup_groups[i] == 601;
		}
		CHECK(s80 && s600 && s601);
	}
	memset(&el, 0, sizeof(el));
	el.el_uid = 501;
	el.el_sup_grp_cnt = 4;
	el.el_sup_groups[0] = 601;
	el.el_sup_groups[1] = 4444;
	el.el_sup_groups[2] = 80;
	el.el_sup_groups[3] = 601;
	ask(&od, &el, KAUTH_EXTLOOKUP_VALID_UID | KAUTH_EXTLOOKUP_VALID_SUPGRPS | ALL_WANTS |
	    KAUTH_EXTLOOKUP_WANT_SUPGRPS, NULL, out);
	CHECK((el.el_flags & KAUTH_EXTLOOKUP_VALID_SUPGRPS) && el.el_sup_grp_cnt == 4 &&
	    el.el_sup_groups[0] == 601 && el.el_sup_groups[1] == 80 && el.el_sup_groups[2] == 20 &&
	    el.el_sup_groups[3] == 600);
	memset(&el, 0, sizeof(el));
	el.el_uid = 12345;
	el.el_sup_grp_cnt = 1;
	el.el_sup_groups[0] = 20;
	ask(&od, &el, KAUTH_EXTLOOKUP_VALID_UID | KAUTH_EXTLOOKUP_VALID_SUPGRPS | ALL_WANTS |
	    KAUTH_EXTLOOKUP_WANT_SUPGRPS, NULL, out);
	CHECK((el.el_flags & KAUTH_EXTLOOKUP_VALID_UID) && !(el.el_flags & KAUTH_EXTLOOKUP_VALID_SUPGRPS));
	for (n = 0; n < 20; n++) {
		snprintf(name, sizeof(name), "many%d", n);
		snprintf(out, sizeof(out), "%d", 700 + n);
		put_record(&od, RT_GROUPS, make_group(name, out, NULL, "pie"));
	}
	memset(&el, 0, sizeof(el));
	el.el_uid = 501;
	el.el_sup_grp_cnt = 99;
	ask(&od, &el, KAUTH_EXTLOOKUP_VALID_UID | KAUTH_EXTLOOKUP_VALID_SUPGRPS |
	    KAUTH_EXTLOOKUP_WANT_SUPGRPS, NULL, out);
	CHECK((el.el_flags & KAUTH_EXTLOOKUP_VALID_SUPGRPS) && el.el_sup_grp_cnt == 16 &&
	    el.el_sup_groups[0] == 20);

	CHECK(!ismember(&od, 502, 80));
	memset(&od2, 0, sizeof(od2));
	od2.log = quiet_log;
	CHECK(od_init(&od2, od.store.root) == 0);
	CHECK(!ismember(&od2, 502, 80));
	CHECK(open_node(&od, 0, &n, "/Local/Default", node));
	u = sarr("bob");
	pl_array_append(u, pl_string("nobody"));
	CHECK(set_value(&od, 0, &n, node, OD_RECSTD "Groups", "admin", OD_STD "GroupMembership", u) == 0);
	CHECK(ismember(&od2, 502, 80));
	CHECK(!ismember(&od2, 501, 80));
	CHECK(set_value(&od, 0, &n, node, OD_RECSTD "Groups", "admin", OD_STD "GroupMembership",
	    sarr("pie")) == 0);
	CHECK(!ismember(&od2, 502, 80));
	CHECK(ismember(&od2, 501, 80));
	od_free(&od2);
	teardown(&od, dir);
}

struct fake_kernel {
	struct od_resolver *r;
	int ops[64];
	size_t nops;
	int step;
	uint32_t answers[8];
	char names[8][64];
	size_t nanswers;
	bool deny_register;
	bool deny_on_default;
};

static struct fake_kernel fk;

static void
no_pause(void)
{
}

static int
fail(int e)
{
	errno = e;
	return -1;
}

static int
fake_svc(int op, struct kauth_identity_extlookup *el)
{
	if (fk.nops < sizeof(fk.ops) / sizeof(fk.ops[0])) {
		fk.ops[fk.nops++] = op;
	}
	if (op == KAUTH_EXTLOOKUP_RESULT) {
		if (fk.nanswers < 8) {
			fk.answers[fk.nanswers] = el->el_flags;
			if (el->el_flags & KAUTH_EXTLOOKUP_VALID_PWNAM) {
				snprintf(fk.names[fk.nanswers], sizeof(fk.names[0]), "%s",
				    (const char *)(uintptr_t)el->el_extend);
			}
			fk.nanswers++;
		}
		if (el->el_seqno == 2) {
			atomic_fetch_add(&fk.r->gen, 1);
		}
		return 0;
	}
	if (op != KAUTH_EXTLOOKUP_WORKER) {
		if (op == KAUTH_EXTLOOKUP_REGISTER && fk.deny_register) {
			return fail(EPERM);
		}
		return 0;
	}
	switch (fk.step++) {
	case 0:
		el->el_seqno = 1;
		el->el_flags = KAUTH_EXTLOOKUP_VALID_UID | KAUTH_EXTLOOKUP_WANT_UGUID;
		el->el_uid = 501;
		return 0;
	case 1:
		od_resolver_changed(fk.r);
		el->el_seqno = 2;
		el->el_flags = KAUTH_EXTLOOKUP_VALID_UID | KAUTH_EXTLOOKUP_VALID_GID |
		    KAUTH_EXTLOOKUP_WANT_MEMBERSHIP;
		el->el_uid = 501;
		el->el_gid = 80;
		return 0;
	case 2:
		return fail(EINTR);
	case 3:
		return fail(EIO);
	case 4:
		el->el_seqno = 3;
		el->el_flags = KAUTH_EXTLOOKUP_VALID_PWNAM | KAUTH_EXTLOOKUP_WANT_UID |
		    KAUTH_EXTLOOKUP_WANT_PWNAM;
		snprintf((char *)(uintptr_t)el->el_extend, 64, "pie");
		return 0;
	default:
		fk.deny_register = fk.deny_on_default;
		return fail(EIO);
	}
}

static void
test_resolver_loop(void)
{
	static const int want[] = {
		KAUTH_EXTLOOKUP_REGISTER, KAUTH_CLEAR_CACHES,
		KAUTH_EXTLOOKUP_WORKER, KAUTH_EXTLOOKUP_RESULT,
		KAUTH_EXTLOOKUP_WORKER, KAUTH_CLEAR_CACHES, KAUTH_EXTLOOKUP_RESULT, KAUTH_CLEAR_CACHES,
		KAUTH_EXTLOOKUP_WORKER,
		KAUTH_EXTLOOKUP_WORKER, KAUTH_EXTLOOKUP_REGISTER, KAUTH_CLEAR_CACHES,
		KAUTH_EXTLOOKUP_WORKER, KAUTH_EXTLOOKUP_RESULT,
		KAUTH_EXTLOOKUP_WORKER, KAUTH_EXTLOOKUP_REGISTER,
	};
	char dir[1024];
	struct od od;
	struct od_resolver r;
	size_t i;

	setup_dir(dir, sizeof(dir), &od);
	seed(&od);
	memset(&r, 0, sizeof(r));
	r.od = &od;
	r.svc = fake_svc;
	r.pause = no_pause;
	memset(&fk, 0, sizeof(fk));
	fk.r = &r;
	fk.deny_on_default = true;
	CHECK(od_resolver_run(&r) == -1);
	CHECK(od.store.shared_gen == &r.gen);
	CHECK(fk.nops == sizeof(want) / sizeof(want[0]));
	for (i = 0; i < fk.nops && i < sizeof(want) / sizeof(want[0]); i++) {
		CHECK(fk.ops[i] == want[i]);
	}
	CHECK(fk.nanswers == 3);
	CHECK(fk.answers[0] == (KAUTH_EXTLOOKUP_VALID_UID | KAUTH_EXTLOOKUP_VALID_UGUID |
	    KAUTH_EXTLOOKUP_WANT_UGUID));
	CHECK(fk.answers[1] == (KAUTH_EXTLOOKUP_VALID_UID | KAUTH_EXTLOOKUP_VALID_GID |
	    KAUTH_EXTLOOKUP_WANT_MEMBERSHIP | KAUTH_EXTLOOKUP_VALID_MEMBERSHIP | KAUTH_EXTLOOKUP_ISMEMBER));
	CHECK(fk.answers[2] == (KAUTH_EXTLOOKUP_VALID_UID | KAUTH_EXTLOOKUP_WANT_UID |
	    KAUTH_EXTLOOKUP_WANT_PWNAM | KAUTH_EXTLOOKUP_VALID_PWNAM) && strcmp(fk.names[2], "pie") == 0);
	CHECK(!atomic_load(&r.up));
	fk.nops = 0;
	od_resolver_changed(&r);
	od_resolver_stop(&r);
	CHECK(fk.nops == 0);

	memset(&fk, 0, sizeof(fk));
	fk.r = &r;
	fk.deny_register = true;
	CHECK(od_resolver_run(&r) == -1 && fk.nops == 1 && fk.ops[0] == KAUTH_EXTLOOKUP_REGISTER);

	memset(&fk, 0, sizeof(fk));
	fk.r = &r;
	fk.step = 5;
	atomic_store(&r.stopped, false);
	atomic_store(&r.up, true);
	od_resolver_changed(&r);
	CHECK(fk.nops == 1 && fk.ops[0] == KAUTH_CLEAR_CACHES);
	od_resolver_stop(&r);
	CHECK(fk.nops == 2 && fk.ops[1] == KAUTH_EXTLOOKUP_DEREGISTER && !atomic_load(&r.up));
	od_resolver_stop(&r);
	CHECK(fk.nops == 2);
	CHECK(od_resolver_run(&r) == 0);
	CHECK(fk.nops == 4 && fk.ops[2] == KAUTH_EXTLOOKUP_REGISTER && fk.ops[3] == KAUTH_EXTLOOKUP_DEREGISTER);
	CHECK(!atomic_load(&r.up));
	od_resolver_clear(&r);
	CHECK(fk.nops == 4);
	atomic_store(&r.up, true);
	od_resolver_clear(&r);
	CHECK(fk.nops == 5 && fk.ops[4] == KAUTH_CLEAR_CACHES);
	atomic_store(&r.up, false);

	memset(&fk, 0, sizeof(fk));
	fk.r = &r;
	fk.step = 5;
	atomic_store(&r.stopped, false);
	CHECK(od_resolver_run(&r) == -1);
	CHECK(fk.nops == 3 + 3 * OD_RESOLVER_RETRIES && fk.ops[fk.nops - 1] == KAUTH_EXTLOOKUP_WORKER);
	teardown(&od, dir);
}

static bool fake_clock;
static struct timespec fake_wall, fake_steady;
static int readdir_fail;
static bool opendir_fail;
static const char *fstatat_fail;
static int fstatat_hits;
static bool read_fail;

struct dirent *__real_readdir(DIR *dir);
DIR *__real_opendir(const char *path);
int __real_fstatat(int fd, const char *path, struct stat *st, int flags);
int __real_clock_gettime(clockid_t id, struct timespec *ts);

DIR *
__wrap_opendir(const char *path)
{
	if (opendir_fail) {
		opendir_fail = false;
		errno = EIO;
		return NULL;
	}
	return __real_opendir(path);
}

int
__wrap_fstatat(int fd, const char *path, struct stat *st, int flags)
{
	if (fstatat_fail != NULL && strcmp(path, fstatat_fail) == 0) {
		fstatat_hits++;
		errno = EIO;
		return -1;
	}
	return __real_fstatat(fd, path, st, flags);
}

ssize_t __real_read(int fd, void *buf, size_t n);

ssize_t
__wrap_read(int fd, void *buf, size_t n)
{
	if (read_fail) {
		read_fail = false;
		errno = EIO;
		return -1;
	}
	return __real_read(fd, buf, n);
}

struct dirent *
__wrap_readdir(DIR *dir)
{
	if (readdir_fail > 0 && --readdir_fail == 0) {
		errno = EIO;
		return NULL;
	}
	return __real_readdir(dir);
}

int
__wrap_clock_gettime(clockid_t id, struct timespec *ts)
{
	if (fake_clock && id == CLOCK_REALTIME) {
		*ts = fake_wall;
		return 0;
	}
	if (fake_clock && id == CLOCK_MONOTONIC) {
		*ts = fake_steady;
		return 0;
	}
	return __real_clock_gettime(id, ts);
}

static void
clock_run(time_t sec)
{
	fake_wall.tv_sec += sec;
	fake_steady.tv_sec += sec;
}

static void
clock_step(time_t sec)
{
	fake_wall.tv_sec += sec;
}

static void
dir_mtime(struct od *od, enum rtype t, time_t sec)
{
	char path[1200];
	struct timespec ts[2] = { { 0, UTIME_OMIT }, { sec, 0 } };

	snprintf(path, sizeof(path), "%s/%s", od->store.root, rtype_dir(t));
	CHECK(utimensat(AT_FDCWD, path, ts, 0) == 0);
}

static void
other_write(struct od *od, enum rtype t, pl_t *rec, const char *oldname)
{
	struct store s;
	pid_t pid;
	int status = -1, rc;

	pid = fork();
	if (pid == 0) {
		rc = store_init(&s, od->store.root);
		if (rc == 0) {
			rc = rec != NULL ? store_write(&s, t, rec, oldname) : store_delete(&s, t, oldname);
		}
		_exit(rc == 0 ? 0 : 1);
	}
	CHECK(pid > 0 && waitpid(pid, &status, 0) == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0);
	pl_free(rec);
}

static int64_t
lookup_id(struct od *od, const char *proc, const char *key, const char *name)
{
	pl_t *req = req1("name", pl_string(name)), *r = od_libinfo(od, proc, req);
	const pl_t *v = pl_dict_get(r, key);
	int64_t id = err_of(r) == 0 && pl_is(v, PL_INT) ? v->i : -1;

	pl_free(r);
	pl_free(req);
	return id;
}

static int64_t
pw_uid(struct od *od, const char *name)
{
	return lookup_id(od, "getpwnam", "pw_uid", name);
}

static bool
pw_named(struct od *od, uint32_t uid, const char *name)
{
	pl_t *req = req1("uid", pl_int(uid)), *r = od_libinfo(od, "getpwuid", req);
	const char *s = pl_str(pl_dict_get(r, "pw_name"));
	bool ok = err_of(r) == 0 && s != NULL && strcmp(s, name) == 0;

	pl_free(r);
	pl_free(req);
	return ok;
}

static int64_t
resolve_uid(struct od *od, const char *name)
{
	struct kauth_identity_extlookup el;

	memset(&el, 0, sizeof(el));
	ask(od, &el, KAUTH_EXTLOOKUP_VALID_PWNAM | KAUTH_EXTLOOKUP_WANT_UID, name, NULL);
	return (el.el_flags & KAUTH_EXTLOOKUP_VALID_UID) ? (int64_t)el.el_uid : -1;
}

static void
test_rescan(void)
{
	char dir[1024];
	struct od od, rod;
	struct od_resolver r;
	time_t old = time(NULL) - 10, now;
	pl_t *u;

	setup_dir(dir, sizeof(dir), &od);
	seed(&od);
	dir_mtime(&od, RT_USERS, old);
	dir_mtime(&od, RT_GROUPS, old);
	CHECK(pw_uid(&od, "pie") == 501);

	other_write(&od, RT_USERS, make_user("carol", "710", "20", NULL), NULL);
	CHECK(pw_uid(&od, "carol") == 710);
	dir_mtime(&od, RT_USERS, old);
	CHECK(pw_uid(&od, "carol") == 710);
	other_write(&od, RT_USERS, make_user("carol", "711", "20", NULL), "carol");
	CHECK(pw_uid(&od, "carol") == 711 && pw_named(&od, 711, "carol") && !pw_named(&od, 710, "carol"));
	dir_mtime(&od, RT_USERS, old);
	CHECK(pw_uid(&od, "carol") == 711);
	u = make_user("caz", "711", "20", NULL);
	other_write(&od, RT_USERS, u, "carol");
	CHECK(pw_uid(&od, "carol") == -1 && pw_uid(&od, "caz") == 711 && pw_named(&od, 711, "caz"));
	dir_mtime(&od, RT_USERS, old);
	CHECK(pw_uid(&od, "caz") == 711);
	other_write(&od, RT_USERS, NULL, "caz");
	CHECK(pw_uid(&od, "caz") == -1 && !pw_named(&od, 711, "caz"));
	dir_mtime(&od, RT_USERS, old);
	CHECK(pw_uid(&od, "pie") == 501);

	CHECK(lookup_id(&od, "getgrnam", "gr_gid", "crew") == -1);
	other_write(&od, RT_GROUPS, make_group("crew", "720", NULL, "pie"), NULL);
	CHECK(lookup_id(&od, "getgrnam", "gr_gid", "crew") == 720);
	dir_mtime(&od, RT_GROUPS, old);
	CHECK(lookup_id(&od, "getgrnam", "gr_gid", "crew") == 720);
	other_write(&od, RT_GROUPS, NULL, "crew");
	CHECK(lookup_id(&od, "getgrnam", "gr_gid", "crew") == -1);
	dir_mtime(&od, RT_GROUPS, old);

	other_write(&od, RT_USERS, make_user("dave", "712", "20", NULL), NULL);
	dir_mtime(&od, RT_USERS, old);
	CHECK(pw_uid(&od, "dave") == -1);
	dir_mtime(&od, RT_USERS, old + 1);
	CHECK(pw_uid(&od, "dave") == 712);

	now = time(NULL);
	fake_clock = true;
	fake_wall.tv_sec = now;
	fake_steady.tv_sec = 100;
	dir_mtime(&od, RT_USERS, now);
	CHECK(pw_uid(&od, "dave") == 712);
	other_write(&od, RT_USERS, make_user("erin", "713", "20", NULL), NULL);
	dir_mtime(&od, RT_USERS, now);
	CHECK(pw_uid(&od, "erin") == 713);
	other_write(&od, RT_USERS, make_user("erin", "714", "20", NULL), "erin");
	dir_mtime(&od, RT_USERS, now);
	CHECK(pw_uid(&od, "erin") == 714);
	other_write(&od, RT_USERS, NULL, "erin");
	dir_mtime(&od, RT_USERS, now);
	CHECK(pw_uid(&od, "erin") == -1);
	fake_clock = false;

	memset(&rod, 0, sizeof(rod));
	rod.log = quiet_log;
	CHECK(od_init(&rod, od.store.root) == 0);
	memset(&r, 0, sizeof(r));
	r.od = &rod;
	rod.store.shared_gen = &r.gen;
	dir_mtime(&od, RT_USERS, old);
	CHECK(resolve_uid(&rod, "pie") == 501 && pw_uid(&od, "pie") == 501);
	put_record(&od, RT_USERS, make_user("fay", "715", "20", NULL));
	dir_mtime(&od, RT_USERS, old);
	CHECK(pw_uid(&od, "fay") == 715);
	CHECK(resolve_uid(&rod, "fay") == -1);
	od_resolver_changed(&r);
	CHECK(resolve_uid(&rod, "fay") == 715);
	od_free(&rod);

	u = make_user("gus", "730", "20", NULL);
	pl_array_append(pl_dict_get(u, "name"), pl_string("gustav"));
	pl_array_append(pl_dict_get(u, "name"), pl_string("shared"));
	put_record(&od, RT_USERS, u);
	u = make_user("hal", "730", "21", NULL);
	pl_array_append(pl_dict_get(u, "name"), pl_string("shared"));
	put_record(&od, RT_USERS, u);
	CHECK(store_find(&od.store, RT_USERS, "gustav") == store_find(&od.store, RT_USERS, "gus"));
	CHECK(store_find(&od.store, RT_USERS, "shared") == store_find(&od.store, RT_USERS, "gus"));
	CHECK(store_find_id(&od.store, RT_USERS, "uid", 730) == store_find(&od.store, RT_USERS, "gus"));
	CHECK(store_find_id(&od.store, RT_USERS, "gid", 21) == store_find(&od.store, RT_USERS, "hal"));
	CHECK(store_delete(&od.store, RT_USERS, "gus") == 0);
	CHECK(store_find(&od.store, RT_USERS, "gustav") == NULL);
	CHECK(store_find(&od.store, RT_USERS, "shared") == store_find(&od.store, RT_USERS, "hal"));
	CHECK(store_find_id(&od.store, RT_USERS, "uid", 730) == store_find(&od.store, RT_USERS, "hal"));
	teardown(&od, dir);
}

static void
test_rescan_clock(void)
{
	char dir[1024];
	char path[1200], path2[1200];
	struct od od;
	time_t m;
	pl_t *g;

	fake_clock = true;
	fake_wall.tv_sec = 2000000000;
	fake_steady.tv_sec = 100;
	m = fake_wall.tv_sec - 10;
	setup_dir(dir, sizeof(dir), &od);
	seed(&od);
	dir_mtime(&od, RT_USERS, m);
	dir_mtime(&od, RT_GROUPS, m);
	CHECK(pw_uid(&od, "pie") == 501);
	CHECK(od.store.dirs[RT_USERS].settled);

	other_write(&od, RT_USERS, make_user("kim", "740", "20", NULL), NULL);
	dir_mtime(&od, RT_USERS, m);
	CHECK(pw_uid(&od, "kim") == -1);
	g = make_group("band", "741", NULL, "pie");
	CHECK(store_write(&od.store, RT_GROUPS, g, NULL) == 0);
	pl_free(g);
	CHECK(pw_uid(&od, "kim") == 740);

	clock_run(5);
	CHECK(pw_uid(&od, "kim") == 740);
	CHECK(od.store.dirs[RT_USERS].settled);
	clock_step(-20);
	other_write(&od, RT_USERS, make_user("lee", "742", "20", NULL), NULL);
	dir_mtime(&od, RT_USERS, m);
	CHECK(pw_uid(&od, "lee") == 742);
	CHECK(!od.store.dirs[RT_USERS].settled);
	clock_run(30);
	CHECK(pw_uid(&od, "lee") == 742);
	CHECK(od.store.dirs[RT_USERS].settled);
	clock_step(40);
	other_write(&od, RT_USERS, make_user("max", "743", "20", NULL), NULL);
	dir_mtime(&od, RT_USERS, m);
	CHECK(pw_uid(&od, "max") == 743);

	clock_run(5);
	CHECK(pw_uid(&od, "max") == 743 && od.store.dirs[RT_USERS].settled);
	other_write(&od, RT_USERS, make_user("ned", "744", "20", NULL), NULL);
	dir_mtime(&od, RT_USERS, m + 1);
	readdir_fail = 1;
	CHECK(pw_uid(&od, "pie") == 501);
	CHECK(readdir_fail == 0 && !od.store.dirs[RT_USERS].settled);
	CHECK(pw_uid(&od, "ned") == 744 && pw_uid(&od, "pie") == 501);
	CHECK(od.store.dirs[RT_USERS].settled);

	dir_mtime(&od, RT_USERS, m + 2);
	opendir_fail = true;
	CHECK(pw_uid(&od, "pie") == 501 && pw_uid(&od, "ned") == 744);
	CHECK(!opendir_fail);
	CHECK(od.store.dirs[RT_USERS].settled);
	dir_mtime(&od, RT_USERS, m + 3);
	opendir_fail = true;
	CHECK(pw_uid(&od, "pie") == 501);
	CHECK(!od.store.dirs[RT_USERS].settled);

	CHECK(pw_uid(&od, "ned") == 744 && od.store.dirs[RT_USERS].settled);
	other_write(&od, RT_USERS, make_user("ned", "745", "20", NULL), "ned");
	dir_mtime(&od, RT_USERS, m + 4);
	fstatat_fail = "ned.plist";
	fstatat_hits = 0;
	CHECK(pw_uid(&od, "ned") == 744);
	CHECK(fstatat_hits == 1 && !od.store.dirs[RT_USERS].settled);
	other_write(&od, RT_USERS, NULL, "max");
	other_write(&od, RT_USERS, make_user("ola", "740", "20", NULL), "kim");
	dir_mtime(&od, RT_USERS, m + 4);
	CHECK(pw_uid(&od, "max") == -1 && pw_uid(&od, "kim") == -1 && pw_uid(&od, "ola") == 740);
	CHECK(pw_uid(&od, "ned") == 744 && fstatat_hits > 1 && !od.store.dirs[RT_USERS].settled);
	CHECK(store_delete(&od.store, RT_USERS, "ola") == 0 && pw_uid(&od, "ola") == -1);
	fstatat_fail = NULL;
	CHECK(pw_uid(&od, "ned") == 745 && od.store.dirs[RT_USERS].settled);

	other_write(&od, RT_USERS, make_user("quin", "750", "20", NULL), NULL);
	dir_mtime(&od, RT_USERS, m + 6);
	CHECK(pw_uid(&od, "quin") == 750 && od.store.dirs[RT_USERS].settled);
	other_write(&od, RT_USERS, make_user("ned", "749", "20", NULL), "ned");
	other_write(&od, RT_USERS, NULL, "quin");
	dir_mtime(&od, RT_USERS, m + 5);
	read_fail = true;
	CHECK(pw_uid(&od, "ned") == 745);
	CHECK(store_find(&od.store, RT_USERS, "quin") == NULL);
	CHECK(!read_fail && !od.store.dirs[RT_USERS].settled);
	CHECK(pw_uid(&od, "ned") == 749 && od.store.dirs[RT_USERS].settled);
	other_write(&od, RT_USERS, make_user("ned", "745", "20", NULL), "ned");
	dir_mtime(&od, RT_USERS, m + 4);
	CHECK(pw_uid(&od, "ned") == 745);

	snprintf(path, sizeof(path), "%s/users/ned.plist", od.store.root);
	other_write(&od, RT_USERS, make_user("ned", "746", "20", NULL), "ned");
	CHECK(chmod(path, 0) == 0);
	other_write(&od, RT_USERS, make_user("ola", "747", "20", NULL), NULL);
	snprintf(path2, sizeof(path2), "%s/users/ola.plist", od.store.root);
	CHECK(chmod(path2, 0) == 0);
	dir_mtime(&od, RT_USERS, m + 5);
	if (access(path, R_OK) != 0) {
		CHECK(pw_uid(&od, "ned") == 745 && pw_uid(&od, "ola") == -1);
		CHECK(!od.store.dirs[RT_USERS].settled);
	}
	CHECK(chmod(path, 0600) == 0 && chmod(path2, 0600) == 0);
	CHECK(pw_uid(&od, "ned") == 746 && pw_uid(&od, "ola") == 747);
	CHECK(od.store.dirs[RT_USERS].settled);

	dir_mtime(&od, RT_USERS, fake_wall.tv_sec - 1);
	CHECK(pw_uid(&od, "ola") == 747 && !od.store.dirs[RT_USERS].settled);

	dir_mtime(&od, RT_USERS, m + 6);
	CHECK(pw_uid(&od, "ola") == 747 && od.store.dirs[RT_USERS].settled);
	snprintf(path, sizeof(path), "%s/users", od.store.root);
	snprintf(path2, sizeof(path2), "%s/users.old", od.store.root);
	CHECK(rename(path, path2) == 0 && mkdir(path, 0700) == 0);
	other_write(&od, RT_USERS, make_user("pat", "748", "20", NULL), NULL);
	dir_mtime(&od, RT_USERS, m + 6);
	CHECK(pw_uid(&od, "pat") == 748 && pw_uid(&od, "ola") == -1);

	teardown(&od, dir);
	fake_clock = false;
}

static double
lookups(struct od *od, size_t n)
{
	struct timespec a, b;
	double best = 0, t;
	char name[32];
	bool ok = true;
	size_t i;
	int round;

	for (round = 0; round < 3; round++) {
		clock_gettime(CLOCK_MONOTONIC, &a);
		for (i = 0; i < n; i++) {
			snprintf(name, sizeof(name), "u%zu", i);
			ok = ok && pw_uid(od, name) == (int64_t)(10000 + i);
			ok = ok && pw_named(od, (uint32_t)(10000 + i), name);
			ok = ok && resolve_uid(od, name) == (int64_t)(10000 + i);
		}
		clock_gettime(CLOCK_MONOTONIC, &b);
		t = (double)(b.tv_sec - a.tv_sec) + (double)(b.tv_nsec - a.tv_nsec) / 1e9;
		if (round == 0 || t < best) {
			best = t;
		}
	}
	CHECK(ok);
	return best;
}

static double
many_users(size_t n)
{
	char dir[1024], path[1200], name[32], uid[16];
	struct od od;
	uint8_t *d;
	size_t i, len;
	double t;
	pl_t *u;

	setup_dir(dir, sizeof(dir), &od);
	seed(&od);
	for (i = 0; i < n; i++) {
		snprintf(name, sizeof(name), "u%zu", i);
		snprintf(uid, sizeof(uid), "%zu", 10000 + i);
		u = make_user(name, uid, "20", NULL);
		CHECK(pl_bplist_write(u, &d, &len) == 0);
		pl_free(u);
		snprintf(path, sizeof(path), "%s/users/%s.plist", od.store.root, name);
		write_file(path, d, len);
		free(d);
	}
	dir_mtime(&od, RT_USERS, time(NULL) - 10);
	dir_mtime(&od, RT_GROUPS, time(NULL) - 10);
	CHECK(pw_uid(&od, "pie") == 501);
	t = lookups(&od, n);
	teardown(&od, dir);
	return t;
}

static void
test_scale(void)
{
	double t1 = many_users(1000), t2 = many_users(2000);

	CHECK(t2 < 3 * t1 + 0.01);
	CHECK(t2 < 2.0);
}

static int
cmd_dump(const char *path)
{
	size_t len;
	uint8_t *buf = read_file(path, &len);
	pl_t *p = buf ? pl_bplist_read(buf, len) : NULL;

	free(buf);
	if (p == NULL) {
		puts("INVALID");
		return 1;
	}
	dump(p, stdout);
	putchar('\n');
	pl_free(p);
	return 0;
}

static int
cmd_roundtrip(const char *in, const char *out)
{
	size_t len;
	uint8_t *buf = read_file(in, &len), *o;
	pl_t *p = buf ? pl_bplist_read(buf, len) : NULL;

	free(buf);
	if (p == NULL || pl_bplist_write(p, &o, &len) != 0) {
		return 1;
	}
	write_file(out, o, len);
	free(o);
	pl_free(p);
	return 0;
}

static int
cmd_verify(const char *path, const char *pw)
{
	size_t len;
	uint8_t *buf = read_file(path, &len);
	pl_t *rec = buf ? pl_bplist_read(buf, len) : NULL;
	const pl_t *shd = pl_array_get(pl_dict_get(rec, OD_SHADOW_KEY), 0);
	int r;

	free(buf);
	if (rec == NULL || !rec_valid(rec) || !pl_is(shd, PL_DATA)) {
		puts("INVALID");
		return 2;
	}
	r = shadow_verify(shd->bytes, shd->len, pw, strlen(pw));
	puts(r == 1 ? "OK" : r == 0 ? "MISMATCH" : "INVALID");
	pl_free(rec);
	return r == 1 ? 0 : 1;
}

static int
cmd_shadow(const char *pw, const char *iter, const char *out)
{
	uint8_t *shd;
	size_t len;

	if (shadow_make(pw, strlen(pw), (uint32_t)atoi(iter), &shd, &len) != 0) {
		return 1;
	}
	write_file(out, shd, len);
	free(shd);
	return 0;
}

int
main(int argc, char *argv[])
{
	if (argc == 3 && strcmp(argv[1], "dump") == 0) {
		return cmd_dump(argv[2]);
	}
	if (argc == 4 && strcmp(argv[1], "roundtrip") == 0) {
		return cmd_roundtrip(argv[2], argv[3]);
	}
	if (argc == 4 && strcmp(argv[1], "verify") == 0) {
		return cmd_verify(argv[2], argv[3]);
	}
	if (argc == 5 && strcmp(argv[1], "shadow") == 0) {
		return cmd_shadow(argv[2], argv[3], argv[4]);
	}
	if (argc != 1) {
		fprintf(stderr, "usage: test_od [dump FILE | roundtrip IN OUT | verify RECORD PASSWORD | "
		    "shadow PASSWORD ITERATIONS OUT]\n");
		return 2;
	}
	test_plist();
	test_plist_limits();
	test_pbkdf2();
	test_store();
	test_api();
	test_backoff();
	test_sizes();
	test_creds();
	test_libinfo();
	test_resolver();
	test_resolver_loop();
	test_rescan();
	test_rescan_clock();
	test_scale();
	printf("%d checks, %d failures\n", checks, failures);
	return failures != 0;
}
