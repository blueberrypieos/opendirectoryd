/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 The Blueberry Pie OS Authors
 */
#ifndef OD_OD_H
#define OD_OD_H

#include <sys/types.h>

#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>

#include "plist.h"

enum {
	ODE_SESSION_INVALID = 1005,
	ODE_NODE_UNKNOWN_NAME = 2000,
	ODE_NODE_INVALID = 2003,
	ODE_QUERY_UNSUPPORTED_MATCH = 3101,
	ODE_QUERY_INVALID = 3103,
	ODE_READ_ONLY_NODE = 4000,
	ODE_PERMISSION = 4001,
	ODE_PARAMETER = 4100,
	ODE_INVALID_TYPE = 4101,
	ODE_ALREADY_EXISTS = 4102,
	ODE_NO_LONGER_EXISTS = 4104,
	ODE_ATTR_UNKNOWN_TYPE = 4200,
	ODE_ATTR_NOT_FOUND = 4201,
	ODE_ATTR_SCHEMA = 4202,
	ODE_ATTR_VALUE_NOT_FOUND = 4203,
	ODE_CRED_INVALID = 5000,
	ODE_CRED_NOT_AUTHORIZED = 5101,
	ODE_CRED_PARAMETER = 5102,
	ODE_CRED_FAILED = 5103,
	ODE_ACCOUNT_NOT_FOUND = 5300,
	ODE_ACCOUNT_DISABLED = 5301,
	ODE_ACCOUNT_EXPIRED = 5302,
	ODE_ACCOUNT_TEMP_LOCKED = 5304,
	ODE_PASSWORD_QUALITY = 5402,
	ODE_NOT_SUPPORTED = 10000,
	ODE_PLUGIN = 10001,
	ODE_DAEMON = 10002,
};

enum {
	OD_MATCH_ANY = 0x0001,
	OD_MATCH_EQUAL = 0x2001,
	OD_MATCH_BEGINS = 0x2002,
	OD_MATCH_ENDS = 0x2003,
	OD_MATCH_CONTAINS = 0x2004,
	OD_MATCH_GREATER = 0x2006,
	OD_MATCH_LESS = 0x2007,
	OD_MATCH_INSENSITIVE = 0x0100,
};

#define OD_STD "dsAttrTypeStandard:"
#define OD_NATIVE "dsAttrTypeNative:"
#define OD_RECSTD "dsRecTypeStandard:"
#define OD_ATTR_ALL "dsAttributesAll"
#define OD_ATTR_STD_ALL "dsAttributesStandardAll"
#define OD_ATTR_NATIVE_ALL "dsAttributesNativeAll"
#define OD_LOCAL_NODE "/Local/Default"
#define OD_SEARCH_NODE "/Search"
#define OD_DEFAULT_ROOT "/var/db/dslocal/nodes/Default"
#define OD_ADMIN_GROUP "admin"
#define OD_SHADOW_KEY "ShadowHashData"
#define OD_HIDDEN_PASSWORD "********"
#define OD_ITERATIONS 40000
#define OD_MAX_NAME 240
#define OD_EVERYONE_GID 12
#define OD_RESOLVER_TTL 300
#define OD_RESOLVER_RETRIES 5

enum rtype {
	RT_USERS,
	RT_GROUPS,
	RT_COUNT,
};

struct entry {
	char *file;
	dev_t dev;
	ino_t ino;
	off_t size;
	struct timespec mtime;
	pl_t *rec;
	bool seen;
};

struct slot {
	const char *key;
	uint32_t id;
	size_t idx;
};

struct index {
	struct slot *s;
	size_t size;
};

struct rdir {
	struct entry *e;
	size_t count;
	size_t cap;
	struct index files;
	struct index names;
	struct index ids;
	bool settled;
	dev_t dev;
	ino_t ino;
	struct timespec mtime;
	int64_t offset;
	unsigned gen;
	unsigned shared_gen;
};

struct store {
	char *root;
	struct rdir dirs[RT_COUNT];
	unsigned gen;
	atomic_uint *shared_gen;
};

struct fail {
	char *name;
	unsigned count;
	time_t last;
};

struct fails {
	struct fail *e;
	size_t count;
	size_t cap;
};

struct node {
	struct node *next;
	uint8_t uuid[16];
	void *owner;
	bool search;
	char *creds;
	uint8_t *gen;
	size_t genlen;
};

struct od {
	struct store store;
	struct node *nodes;
	struct fails known;
	struct fails unknown;
	const char *shells_path;
	const char *passwd_path;
	const char *master_passwd_path;
	const char *group_path;
	uint32_t iterations;
	void (*changed)(void);
	void (*log)(int level, const char *fmt, ...);
	time_t (*now)(void);
};

struct od_caller {
	uid_t euid;
	pid_t pid;
	void *peer;
};

struct kauth_identity_extlookup;

struct od_resolver {
	struct od *od;
	int (*svc)(int opcode, struct kauth_identity_extlookup *el);
	void (*pause)(void);
	atomic_uint gen;
	atomic_bool up;
	atomic_bool stopped;
};

typedef void (*od_send_t)(void *ctx, uint64_t error, bool complete, const pl_t *reply);

enum {
	OD_LOG_ERR = 3,
	OD_LOG_WARNING = 4,
	OD_LOG_NOTICE = 5,
	OD_LOG_INFO = 6,
};

const char *rtype_name(enum rtype t);
const char *rtype_dir(enum rtype t);
int rtype_from_name(const char *name, enum rtype *t);

const char *attr_key(const char *attr, bool *known);
char *attr_name(const char *key);
bool attr_is_standard_key(const char *key);
bool attr_is_virtual(const char *attr);

int store_init(struct store *s, const char *root);
void store_free(struct store *s);
void store_refresh(struct store *s, enum rtype t);
size_t store_count(const struct store *s, enum rtype t);
pl_t *store_rec(const struct store *s, enum rtype t, size_t i);
pl_t *store_find(struct store *s, enum rtype t, const char *name);
pl_t *store_find_value(struct store *s, enum rtype t, const char *key, const char *value);
pl_t *store_find_id(struct store *s, enum rtype t, const char *key, uint32_t id);
bool store_file_name(const struct store *s, enum rtype t, const pl_t *rec, char *buf, size_t size);
int store_write(struct store *s, enum rtype t, const pl_t *rec, const char *oldname);
int store_delete(struct store *s, enum rtype t, const char *name);
bool store_valid_name(const char *name);

const char *rec_first(const pl_t *rec, const char *key);
bool rec_has(const pl_t *rec, const char *key, const char *value);
bool rec_id(const pl_t *rec, const char *key, uint32_t *id);
bool rec_name_matches(const pl_t *rec, const char *name);
bool rec_valid(const pl_t *rec);

int shadow_make(const char *password, size_t len, uint32_t iterations, uint8_t **out, size_t *outlen);
int shadow_verify(const uint8_t *shd, size_t len, const char *password, size_t pwlen);
void shadow_dummy(const char *password, size_t len, uint32_t iterations);
bool od_consttime_equal(const uint8_t *a, const uint8_t *b, size_t len);

unsigned backoff_remaining(struct od *od, const char *name, bool known);
void backoff_failed(struct od *od, const char *name, bool known);
void backoff_succeeded(struct od *od, const char *name);
void backoff_free(struct od *od);

bool uuid_parse_text(const char *s, uint8_t uu[16]);
void uuid_text(const uint8_t uu[16], char out[37]);
void uuid_random(uint8_t uu[16]);
bool parse_id(const char *s, uint32_t *id);
bool name_in_file(const char *path, const char *name);

void od_compat_uuid(enum rtype t, uint32_t id, uint8_t uu[16]);
bool od_parse_compat(const uint8_t uu[16], enum rtype *t, uint32_t *id);
bool od_rec_uuid(const pl_t *rec, enum rtype t, uint8_t uu[16]);
const pl_t *od_find_uuid(struct od *od, enum rtype t, const uint8_t uu[16]);
bool od_is_member(struct od *od, const pl_t *user, const pl_t *group);
bool od_user_is_admin(struct od *od, const pl_t *user);
pl_t *od_user_groups(struct od *od, const pl_t *user, uint32_t max);

int od_init(struct od *od, const char *root);
void od_api(struct od *od, const struct od_caller *caller, const uint8_t session[16],
    const uint8_t node[16], const uint8_t *req, size_t reqlen, od_send_t send, void *ctx);
void od_free(struct od *od);
void od_peer_gone(struct od *od, void *peer);
pl_t *od_libinfo(struct od *od, const char *proc, const pl_t *request);
pl_t *od_membership(struct od *od, const char *proc, const pl_t *request);

void od_resolve(struct od *od, struct kauth_identity_extlookup *el, const char *name, char *out,
    size_t outsize);
int od_resolver_run(struct od_resolver *r);
void od_resolver_changed(struct od_resolver *r);
void od_resolver_clear(struct od_resolver *r);
void od_resolver_stop(struct od_resolver *r);

#endif
