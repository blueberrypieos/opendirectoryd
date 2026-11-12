/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 The Blueberry Pie OS Authors
 */
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "od.h"

#define MAX_NODES_PER_PEER 512
#define MAX_PASSWORD 1024
#define MAX_REQUEST (1024 * 1024)
#define MAX_SELF_VALUES 16
#define MAX_SELF_VALUE 1024
#define DISABLED_PREFIX ";DisabledUser;"
#define SHADOW_AUTHORITY ";ShadowHash;HASHLIST:<SALTED-SHA512-PBKDF2>"

struct call {
	struct od *od;
	const struct od_caller *caller;
	struct node *node;
	const char *fn;
	const pl_t *params;
	od_send_t send;
	void *ctx;
};

struct ident {
	uid_t euid;
	const char *creds;
	bool root;
	bool admin;
};

static const char *const self_keys[] = {
	"shell", "realname", "building", "phonenumber", "homephonenumber", "picture",
};

static const pl_t *
param(const struct call *c, size_t i)
{
	const pl_t *slot = pl_array_get(c->params, i);

	return (pl_is(slot, PL_ARRAY) && slot->count == 1) ? slot->items[0] : NULL;
}

static const char *
param_str(const struct call *c, size_t i)
{
	return pl_str(param(c, i));
}

static pl_t *
results(size_t n, ...)
{
	pl_t *r = pl_array(), *slot, *v;
	va_list ap;
	size_t i;

	va_start(ap, n);
	for (i = 0; i < n; i++) {
		v = va_arg(ap, pl_t *);
		slot = pl_array();
		if (v != NULL) {
			pl_array_append(slot, v);
		}
		pl_array_append(r, slot);
	}
	va_end(ap);
	return r;
}

static void
send_reply(struct call *c, const char *fn, uint64_t error, bool complete, pl_t *res)
{
	pl_t *d = pl_dict();

	pl_dict_set(d, "funcname", pl_string(fn));
	pl_dict_set(d, "results", res != NULL ? res : pl_array());
	c->send(c->ctx, error, complete, d);
	pl_free(d);
}

static void
reply(struct call *c, uint64_t error, pl_t *res)
{
	send_reply(c, c->fn, error, true, res);
}

static void
reply_error(struct call *c, uint64_t error, size_t errslot, pl_t *info)
{
	pl_t *r = pl_array(), *slot;
	size_t i;

	for (i = 0; i <= errslot; i++) {
		slot = pl_array();
		if (i == errslot && info != NULL) {
			pl_array_append(slot, info);
		}
		pl_array_append(r, slot);
	}
	reply(c, error, r);
}

static pl_t *
backoff_info(unsigned seconds)
{
	pl_t *d = pl_dict();

	pl_dict_set(d, "BackOffSeconds", pl_int(seconds));
	return d;
}

static uint64_t
write_error(void)
{
	return errno == EFBIG ? ODE_ATTR_SCHEMA : ODE_PLUGIN;
}

static bool
is_self(const struct ident *id, const pl_t *user)
{
	uint32_t uid;

	if (id->creds != NULL && rec_name_matches(user, id->creds)) {
		return true;
	}
	return rec_id(user, "uid", &uid) && uid == id->euid;
}

static const char *
rec_name(const pl_t *rec)
{
	return rec_first(rec, "name");
}

static bool
is_disabled(const pl_t *user)
{
	const char *a = rec_first(user, "authentication_authority");

	return a != NULL && strncasecmp(a, DISABLED_PREFIX, strlen(DISABLED_PREFIX)) == 0;
}

static bool
is_expired(struct call *c, const pl_t *user)
{
	const char *e = rec_first(user, "expire");
	char *end;
	long long v;

	if (e == NULL) {
		return false;
	}
	v = strtoll(e, &end, 10);
	return *end == '\0' && v > 0 && (long long)c->od->now() > v;
}

static void
drop_creds(struct node *n)
{
	free(n->creds);
	n->creds = NULL;
	if (n->gen != NULL) {
		od_wipe(n->gen, n->genlen);
		free(n->gen);
	}
	n->gen = NULL;
	n->genlen = 0;
}

static const pl_t *
shadow_of(const pl_t *user)
{
	const pl_t *shd = pl_array_get(pl_dict_get(user, OD_SHADOW_KEY), 0);

	return pl_is(shd, PL_DATA) ? shd : NULL;
}

static bool
creds_current(struct call *c, const pl_t *user)
{
	const pl_t *shd = shadow_of(user);
	const struct node *n = c->node;

	return !is_disabled(user) && !is_expired(c, user) && shd != NULL && n->gen != NULL &&
	    shd->len == n->genlen && memcmp(shd->bytes, n->gen, n->genlen) == 0;
}

static void
ident_of(struct call *c, struct ident *id)
{
	const pl_t *user;
	uint32_t uid;

	memset(id, 0, sizeof(*id));
	id->euid = c->caller->euid;
	id->root = id->euid == 0;
	id->creds = c->node != NULL ? c->node->creds : NULL;
	if (id->creds != NULL) {
		user = store_find(&c->od->store, RT_USERS, id->creds);
		if (user == NULL || !creds_current(c, user)) {
			c->od->log(OD_LOG_INFO, "node credentials for %s dropped (pid %d, uid %u)", id->creds,
			    (int)c->caller->pid, (unsigned)c->caller->euid);
			drop_creds(c->node);
			id->creds = NULL;
		} else {
			if (rec_id(user, "uid", &uid) && uid == 0) {
				id->root = true;
			}
			id->admin = od_user_is_admin(c->od, user);
		}
	}
	if (id->root) {
		id->admin = true;
	}
}

static uint64_t
check_password(struct call *c, const pl_t *user, const char *given, const char *pw, pl_t **info)
{
	const char *name = user != NULL ? rec_name(user) : given;
	const pl_t *shd;
	unsigned wait;
	size_t len = strlen(pw);
	int r = -1;

	*info = NULL;
	wait = backoff_remaining(c->od, name, user != NULL);
	if (wait > 0) {
		*info = backoff_info(wait);
		c->od->log(OD_LOG_WARNING, "%s: %s is locked for %u s after failed attempts (pid %d)",
		    c->fn, name, wait, (int)c->caller->pid);
		return ODE_ACCOUNT_TEMP_LOCKED;
	}
	if (user == NULL) {
		shadow_dummy(pw, len, c->od->iterations);
		backoff_failed(c->od, name, false);
		c->od->log(OD_LOG_WARNING, "%s: no user %s (pid %d, uid %u)", c->fn, name,
		    (int)c->caller->pid, (unsigned)c->caller->euid);
		return ODE_CRED_INVALID;
	}
	if (is_disabled(user)) {
		shadow_dummy(pw, len, c->od->iterations);
		c->od->log(OD_LOG_WARNING, "%s: %s is disabled (pid %d)", c->fn, name, (int)c->caller->pid);
		return ODE_ACCOUNT_DISABLED;
	}
	shd = pl_array_get(pl_dict_get(user, OD_SHADOW_KEY), 0);
	if (pl_is(shd, PL_DATA)) {
		r = shadow_verify(shd->bytes, shd->len, pw, len);
	}
	if (r < 0) {
		shadow_dummy(pw, len, c->od->iterations);
	}
	if (r == 1) {
		backoff_succeeded(c->od, name);
		return 0;
	}
	backoff_failed(c->od, name, true);
	c->od->log(OD_LOG_WARNING, "%s: wrong password for %s (pid %d, uid %u)", c->fn, name,
	    (int)c->caller->pid, (unsigned)c->caller->euid);
	return ODE_CRED_INVALID;
}

static struct node *
find_node(struct od *od, const uint8_t uu[16], void *owner)
{
	struct node *n;

	for (n = od->nodes; n != NULL; n = n->next) {
		if (n->owner == owner && memcmp(n->uuid, uu, 16) == 0) {
			return n;
		}
	}
	return NULL;
}

static void
free_node(struct node *n)
{
	drop_creds(n);
	free(n);
}

void
od_peer_gone(struct od *od, void *peer)
{
	struct node **pp = &od->nodes, *n;

	while ((n = *pp) != NULL) {
		if (n->owner == peer) {
			*pp = n->next;
			free_node(n);
		} else {
			pp = &n->next;
		}
	}
}

static void
changed(struct call *c, const char *what, enum rtype t, const char *name, const char *detail)
{
	c->od->log(OD_LOG_NOTICE, "%s %s %s%s%s by uid %u (pid %d)", what, t == RT_USERS ? "user" : "group",
	    name, detail ? " " : "", detail ? detail : "", (unsigned)c->caller->euid, (int)c->caller->pid);
	if (c->od->changed != NULL) {
		c->od->changed();
	}
}

static int
lookup_record(struct call *c, enum rtype *t, const pl_t **rec)
{
	if (rtype_from_name(param_str(c, 0), t) != 0) {
		return ODE_INVALID_TYPE;
	}
	if (param_str(c, 1) == NULL) {
		return ODE_PARAMETER;
	}
	*rec = store_find(&c->od->store, *t, param_str(c, 1));
	return *rec != NULL ? 0 : ODE_NO_LONGER_EXISTS;
}

static pl_t *
export_record(struct call *c, enum rtype t, const pl_t *rec, const pl_t *want, bool root)
{
	bool all = false, std = false, native = false, known, standard;
	pl_t *out = pl_dict(), *a;
	const char *w, *key;
	size_t i;
	char *name;

	a = pl_array();
	pl_array_append(a, pl_string(rtype_name(t)));
	pl_dict_set(out, OD_STD "RecordType", a);
	a = pl_array();
	pl_array_append(a, pl_string(OD_LOCAL_NODE));
	pl_dict_set(out, OD_STD "AppleMetaNodeLocation", a);
	pl_dict_set(out, OD_STD "RecordName", pl_copy(pl_dict_get(rec, "name")));
	for (i = 0; want != NULL && i < want->count; i++) {
		w = pl_str(want->items[i]);
		if (w == NULL) {
			continue;
		}
		all |= strcmp(w, OD_ATTR_ALL) == 0;
		std |= strcmp(w, OD_ATTR_STD_ALL) == 0;
		native |= strcmp(w, OD_ATTR_NATIVE_ALL) == 0;
	}
	std |= all;
	native |= all;
	for (i = 0; (std || native) && i < rec->count; i++) {
		key = rec->keys[i];
		if (strcmp(key, OD_SHADOW_KEY) == 0) {
			continue;
		}
		standard = attr_is_standard_key(key);
		if ((standard && !std) || (!standard && !native)) {
			continue;
		}
		name = attr_name(key);
		pl_dict_set(out, name, pl_copy(rec->items[i]));
		free(name);
	}
	for (i = 0; want != NULL && i < want->count; i++) {
		w = pl_str(want->items[i]);
		if (w == NULL || attr_is_virtual(w) || pl_dict_get(out, w) != NULL) {
			continue;
		}
		key = attr_key(w, &known);
		if (!known || pl_dict_get(rec, key) == NULL) {
			continue;
		}
		if (strcmp(key, OD_SHADOW_KEY) == 0 && !root) {
			continue;
		}
		pl_dict_set(out, w, pl_copy(pl_dict_get(rec, key)));
	}
	return out;
}

static bool
num(const char *s, long long *v)
{
	char *end;

	if (s == NULL || *s == '\0') {
		return false;
	}
	errno = 0;
	*v = strtoll(s, &end, 10);
	return errno == 0 && *end == '\0';
}

static bool
match_value(const pl_t *v, const pl_t *q, uint32_t mt)
{
	bool ci = (mt & OD_MATCH_INSENSITIVE) != 0;
	const char *a, *b;
	size_t la, lb;
	long long na, nb;
	int cmp;

	mt &= ~(uint32_t)OD_MATCH_INSENSITIVE;
	if (pl_is(v, PL_DATA) || pl_is(q, PL_DATA)) {
		return mt == OD_MATCH_EQUAL && v->len == q->len && memcmp(v->bytes, q->bytes, v->len) == 0;
	}
	a = pl_str(v);
	b = pl_str(q);
	if (a == NULL || b == NULL) {
		return false;
	}
	la = strlen(a);
	lb = strlen(b);
	switch (mt) {
	case OD_MATCH_EQUAL:
		return (ci ? strcasecmp(a, b) : strcmp(a, b)) == 0;
	case OD_MATCH_BEGINS:
		return la >= lb && (ci ? strncasecmp(a, b, lb) : strncmp(a, b, lb)) == 0;
	case OD_MATCH_ENDS:
		return la >= lb && (ci ? strcasecmp(a + la - lb, b) : strcmp(a + la - lb, b)) == 0;
	case OD_MATCH_CONTAINS:
		return (ci ? strcasestr(a, b) : strstr(a, b)) != NULL;
	case OD_MATCH_GREATER:
	case OD_MATCH_LESS:
		if (num(a, &na) && num(b, &nb)) {
			cmp = na < nb ? -1 : na > nb;
		} else {
			cmp = strcmp(a, b);
		}
		return mt == OD_MATCH_GREATER ? cmp > 0 : cmp < 0;
	}
	return false;
}

static bool
valid_match(uint32_t mt)
{
	switch (mt) {
	case OD_MATCH_ANY:
	case OD_MATCH_EQUAL:
	case OD_MATCH_BEGINS:
	case OD_MATCH_ENDS:
	case OD_MATCH_CONTAINS:
	case OD_MATCH_GREATER:
	case OD_MATCH_LESS:
	case OD_MATCH_EQUAL | OD_MATCH_INSENSITIVE:
	case OD_MATCH_BEGINS | OD_MATCH_INSENSITIVE:
	case OD_MATCH_ENDS | OD_MATCH_INSENSITIVE:
	case OD_MATCH_CONTAINS | OD_MATCH_INSENSITIVE:
		return true;
	}
	return false;
}

static bool
values_match(const pl_t *vals, const pl_t *query, uint32_t mt)
{
	size_t i, j;

	for (i = 0; vals != NULL && i < vals->count; i++) {
		for (j = 0; j < query->count; j++) {
			if (match_value(vals->items[i], query->items[j], mt)) {
				return true;
			}
		}
	}
	return false;
}

static bool
record_matches(enum rtype t, const pl_t *rec, const char *attr, uint32_t mt, const pl_t *query,
    bool root)
{
	const char *key;
	bool known, hit = false;
	pl_t *tmp;
	size_t i;

	if (mt == OD_MATCH_ANY) {
		return true;
	}
	if (attr == NULL || query == NULL) {
		return false;
	}
	if (strcmp(attr, OD_STD "RecordType") == 0 || strcmp(attr, OD_STD "AppleMetaNodeLocation") == 0) {
		tmp = pl_array();
		pl_array_append(tmp, pl_string(strcmp(attr, OD_STD "RecordType") == 0 ? rtype_name(t) :
		    OD_LOCAL_NODE));
		hit = values_match(tmp, query, mt);
		pl_free(tmp);
		return hit;
	}
	if (strcmp(attr, OD_ATTR_ALL) == 0 || strcmp(attr, OD_ATTR_STD_ALL) == 0 ||
	    strcmp(attr, OD_ATTR_NATIVE_ALL) == 0) {
		for (i = 0; i < rec->count && !hit; i++) {
			if (strcmp(rec->keys[i], OD_SHADOW_KEY) != 0) {
				hit = values_match(rec->items[i], query, mt);
			}
		}
		return hit;
	}
	key = attr_key(attr, &known);
	if (!known || (strcmp(key, OD_SHADOW_KEY) == 0 && !root)) {
		return false;
	}
	return values_match(pl_dict_get(rec, key), query, mt);
}

static pl_t *
as_array(const pl_t *v)
{
	pl_t *a;

	if (v == NULL) {
		return NULL;
	}
	if (pl_is(v, PL_ARRAY)) {
		return pl_copy(v);
	}
	a = pl_array();
	pl_array_append(a, pl_copy(v));
	return a;
}

static void
fn_query(struct call *c)
{
	const pl_t *types = param(c, 0), *query = param(c, 3), *want = param(c, 4), *mtp = param(c, 2);
	const pl_t *maxp = param(c, 5), *rec;
	const char *attr = param_str(c, 1);
	struct ident id;
	pl_t *found = pl_array(), *one;
	bool use[RT_COUNT] = { false, false };
	uint8_t quuid[16];
	uint32_t mt;
	int64_t max = 0;
	enum rtype t;
	size_t i;

	pl_t *wtypes = NULL, *wquery = NULL, *wwant = NULL;

	if (!pl_is(mtp, PL_INT) || !valid_match((uint32_t)mtp->i)) {
		pl_free(found);
		reply_error(c, ODE_QUERY_UNSUPPORTED_MATCH, 1, NULL);
		return;
	}
	mt = (uint32_t)mtp->i;
	if (pl_is(maxp, PL_INT) && maxp->i > 0) {
		max = maxp->i;
	}
	types = wtypes = as_array(types);
	query = wquery = as_array(query);
	want = wwant = as_array(want);
	for (i = 0; types != NULL && i < types->count; i++) {
		if (rtype_from_name(pl_str(types->items[i]), &t) == 0) {
			use[t] = true;
		}
	}
	if (types == NULL) {
		use[RT_USERS] = use[RT_GROUPS] = true;
	}
	ident_of(c, &id);
	for (t = 0; t < RT_COUNT; t++) {
		if (!use[t]) {
			continue;
		}
		for (i = 0; i < store_count(&c->od->store, t); i++) {
			rec = store_rec(&c->od->store, t, i);
			if (rec == NULL || !record_matches(t, rec, attr, mt, query, id.root)) {
				continue;
			}
			if (max > 0 && (int64_t)found->count >= max) {
				break;
			}
			pl_array_append(found, export_record(c, t, rec, want, id.root));
		}
	}
	uuid_random(quuid);
	send_reply(c, "ODQueryCreateWithNode", 0, found->count == 0,
	    results(2, pl_data(quuid, 16), NULL));
	for (i = 0; i < found->count; i++) {
		one = found->items[i];
		found->items[i] = NULL;
		send_reply(c, "ODQueryResponse", 0, i + 1 == found->count,
		    results(3, pl_data(quuid, 16), one, NULL));
	}
	pl_free(found);
	pl_free(wtypes);
	pl_free(wquery);
	pl_free(wwant);
}

static void
fn_node_create(struct call *c)
{
	const char *name = param_str(c, 0);
	struct node *n;
	size_t count = 0;

	if (name == NULL) {
		reply_error(c, ODE_PARAMETER, 1, NULL);
		return;
	}
	if (strcmp(name, OD_LOCAL_NODE) != 0 && strcmp(name, OD_SEARCH_NODE) != 0) {
		reply_error(c, ODE_NODE_UNKNOWN_NAME, 1, NULL);
		return;
	}
	for (n = c->od->nodes; n != NULL; n = n->next) {
		count += n->owner == c->caller->peer;
	}
	if (count >= MAX_NODES_PER_PEER) {
		c->od->log(OD_LOG_WARNING, "pid %d has too many open nodes", (int)c->caller->pid);
		reply_error(c, ODE_PLUGIN, 1, NULL);
		return;
	}
	n = calloc(1, sizeof(*n));
	if (n == NULL) {
		abort();
	}
	uuid_random(n->uuid);
	n->owner = c->caller->peer;
	n->search = strcmp(name, OD_SEARCH_NODE) == 0;
	n->next = c->od->nodes;
	c->od->nodes = n;
	reply(c, 0, results(2, pl_data(n->uuid, 16), NULL));
}

static void
fn_node_release(struct call *c)
{
	struct node **pp, *n;

	for (pp = &c->od->nodes; (n = *pp) != NULL; pp = &n->next) {
		if (n == c->node) {
			*pp = n->next;
			free_node(n);
			break;
		}
	}
	c->node = NULL;
	reply(c, 0, NULL);
}

static void
fn_subnodes(struct call *c)
{
	pl_t *a = pl_array();

	if (c->node->search) {
		pl_array_append(a, pl_string(OD_LOCAL_NODE));
	}
	reply(c, 0, results(2, a, NULL));
}

static void
fn_unreachable(struct call *c)
{
	reply(c, 0, results(2, NULL, NULL));
}

static void
fn_node_names(struct call *c)
{
	pl_t *a = pl_array();

	pl_array_append(a, pl_string(OD_LOCAL_NODE));
	pl_array_append(a, pl_string(OD_SEARCH_NODE));
	reply(c, 0, results(2, a, NULL));
}

static void
fn_set_credentials(struct call *c)
{
	const char *type = param_str(c, 0), *name = param_str(c, 1), *pw = param_str(c, 2);
	const pl_t *user, *shd;
	pl_t *info = NULL;
	uint64_t err;

	drop_creds(c->node);
	if ((type != NULL && strcmp(type, rtype_name(RT_USERS)) != 0) || name == NULL || pw == NULL ||
	    strlen(pw) > MAX_PASSWORD) {
		reply_error(c, ODE_CRED_PARAMETER, 1, NULL);
		return;
	}
	user = store_find(&c->od->store, RT_USERS, name);
	err = check_password(c, user, name, pw, &info);
	if (err == ODE_ACCOUNT_DISABLED || err == ODE_ACCOUNT_NOT_FOUND) {
		err = ODE_CRED_INVALID;
	}
	if (err == 0 && is_expired(c, user)) {
		c->od->log(OD_LOG_WARNING, "%s: %s has expired (pid %d)", c->fn, rec_name(user),
		    (int)c->caller->pid);
		err = ODE_CRED_INVALID;
	}
	if (err != 0) {
		reply_error(c, err, 1, info);
		return;
	}
	shd = shadow_of(user);
	c->node->creds = strdup(rec_name(user));
	c->node->gen = malloc(shd->len);
	if (c->node->creds == NULL || c->node->gen == NULL) {
		abort();
	}
	memcpy(c->node->gen, shd->bytes, shd->len);
	c->node->genlen = shd->len;
	c->od->log(OD_LOG_INFO, "node credentials for %s (pid %d, uid %u)", rec_name(user),
	    (int)c->caller->pid, (unsigned)c->caller->euid);
	reply(c, 0, NULL);
}

static void
fn_verify(struct call *c)
{
	const char *pw = param_str(c, 3);
	const pl_t *user;
	pl_t *info = NULL;
	enum rtype t;
	uint64_t err;

	err = lookup_record(c, &t, &user);
	if (err == 0 && t != RT_USERS) {
		err = ODE_INVALID_TYPE;
	}
	if (err == 0 && (pw == NULL || strlen(pw) > MAX_PASSWORD)) {
		err = ODE_CRED_PARAMETER;
	}
	if (err == 0) {
		err = check_password(c, user, rec_name(user), pw, &info);
	}
	reply_error(c, err, 1, info);
}

static void
fn_auth_allowed(struct call *c)
{
	const pl_t *user;
	pl_t *info = NULL;
	unsigned wait;
	enum rtype t;
	uint64_t err;

	err = lookup_record(c, &t, &user);
	if (err == 0 && t != RT_USERS) {
		err = ODE_INVALID_TYPE;
	}
	if (err == 0) {
		if (is_disabled(user)) {
			err = ODE_ACCOUNT_DISABLED;
		} else if (is_expired(c, user)) {
			err = ODE_ACCOUNT_EXPIRED;
		} else if ((wait = backoff_remaining(c->od, rec_name(user), true)) > 0) {
			err = ODE_ACCOUNT_TEMP_LOCKED;
			info = backoff_info(wait);
		}
	}
	reply_error(c, err, 1, info);
}

static pl_t *
string_array(const char *s)
{
	pl_t *a = pl_array();

	pl_array_append(a, pl_string(s));
	return a;
}

static uint64_t
set_password(struct call *c, const pl_t *user, const char *pw)
{
	const pl_t *old = pl_dict_get(user, "authentication_authority");
	char fname[256];
	uint8_t *shd;
	size_t len, i;
	pl_t *rec, *auth;
	bool disabled = is_disabled(user);
	const char *s;
	uint64_t err;
	int rc;

	if (shadow_make(pw, strlen(pw), c->od->iterations, &shd, &len) != 0) {
		return ODE_CRED_FAILED;
	}
	rec = pl_copy(user);
	auth = pl_array();
	pl_array_append(auth, pl_string(disabled ? DISABLED_PREFIX SHADOW_AUTHORITY : SHADOW_AUTHORITY));
	for (i = 0; old != NULL && i < old->count; i++) {
		s = pl_str(old->items[i]);
		if (s != NULL && strstr(s, ";ShadowHash;") == NULL && strcasecmp(s, DISABLED_PREFIX) != 0) {
			pl_array_append(auth, pl_copy(old->items[i]));
		}
	}
	pl_dict_set(rec, "authentication_authority", auth);
	pl_dict_set(rec, "passwd", string_array(OD_HIDDEN_PASSWORD));
	auth = pl_array();
	pl_array_append(auth, pl_data(shd, len));
	pl_dict_set(rec, OD_SHADOW_KEY, auth);
	od_wipe(shd, len);
	free(shd);
	rc = store_file_name(&c->od->store, RT_USERS, user, fname, sizeof(fname)) ?
	    store_write(&c->od->store, RT_USERS, rec, fname) : -1;
	if (rc != 0) {
		err = write_error();
		c->od->log(OD_LOG_ERR, "cannot write user %s: %s", rec_name(rec), strerror(errno));
		pl_free(rec);
		return err;
	}
	backoff_succeeded(c->od, rec_name(rec));
	changed(c, "password changed for", RT_USERS, rec_name(rec), NULL);
	pl_free(rec);
	return 0;
}

static void
fn_change_password(struct call *c)
{
	const char *old = param_str(c, 3), *pw = param_str(c, 4);
	const pl_t *user;
	struct ident id;
	pl_t *info = NULL;
	enum rtype t;
	uint64_t err;

	err = lookup_record(c, &t, &user);
	if (err == 0 && t != RT_USERS) {
		err = ODE_INVALID_TYPE;
	}
	if (err == 0 && c->node->search) {
		err = ODE_READ_ONLY_NODE;
	}
	if (err == 0 && (pw == NULL || (old != NULL && strlen(old) > MAX_PASSWORD))) {
		err = ODE_CRED_PARAMETER;
	}
	if (err == 0 && (pw[0] == '\0' || strlen(pw) > MAX_PASSWORD)) {
		err = ODE_PASSWORD_QUALITY;
	}
	if (err != 0) {
		reply_error(c, err, 1, NULL);
		return;
	}
	ident_of(c, &id);
	if (old == NULL) {
		if (!id.admin) {
			c->od->log(OD_LOG_WARNING, "%s: uid %u may not set the password of %s", c->fn,
			    (unsigned)id.euid, rec_name(user));
			reply_error(c, ODE_CRED_NOT_AUTHORIZED, 1, NULL);
			return;
		}
	} else {
		if (!id.admin && !is_self(&id, user)) {
			c->od->log(OD_LOG_WARNING, "%s: uid %u may not change the password of %s", c->fn,
			    (unsigned)id.euid, rec_name(user));
			reply_error(c, ODE_CRED_NOT_AUTHORIZED, 1, NULL);
			return;
		}
		err = check_password(c, user, rec_name(user), old, &info);
		if (err != 0) {
			reply_error(c, err, 1, info);
			return;
		}
	}
	reply_error(c, set_password(c, user, pw), 1, NULL);
}

static bool
is_self_key(const char *key)
{
	size_t i;

	for (i = 0; i < sizeof(self_keys) / sizeof(self_keys[0]); i++) {
		if (strcmp(key, self_keys[i]) == 0) {
			return true;
		}
	}
	return false;
}

static bool
shell_listed(struct call *c, const char *want)
{
	char line[1024];
	bool ok = false;
	size_t n;
	FILE *f;

	if (want == NULL) {
		return false;
	}
	if ((f = fopen(c->od->shells_path, "r")) == NULL) {
		return false;
	}
	while (!ok && fgets(line, sizeof(line), f) != NULL) {
		n = strcspn(line, " \t\r\n#");
		line[n] = '\0';
		ok = line[0] == '/' && strcmp(line, want) == 0;
	}
	fclose(f);
	return ok;
}

static bool
shell_allowed(struct call *c, const pl_t *rec, const pl_t *values)
{
	if (!shell_listed(c, rec_first(rec, "shell"))) {
		return false;
	}
	return values != NULL && values->count == 1 && shell_listed(c, pl_str(values->items[0]));
}

static uint64_t
check_values(const char *key, const pl_t *values)
{
	uint8_t uu[16];
	uint32_t id;
	size_t i;

	for (i = 0; i < values->count; i++) {
		if (!pl_is(values->items[i], PL_STRING) && !pl_is(values->items[i], PL_DATA)) {
			return ODE_ATTR_SCHEMA;
		}
	}
	if (strcmp(key, "uid") == 0 || strcmp(key, "gid") == 0) {
		if (values->count != 1 || !parse_id(pl_str(values->items[0]), &id)) {
			return ODE_ATTR_SCHEMA;
		}
	}
	if (strcmp(key, "generateduid") == 0) {
		if (values->count != 1 || !uuid_parse_text(pl_str(values->items[0]), uu)) {
			return ODE_ATTR_SCHEMA;
		}
	}
	if (strcmp(key, OD_SHADOW_KEY) == 0) {
		for (i = 0; i < values->count; i++) {
			if (!pl_is(values->items[i], PL_DATA)) {
				return ODE_ATTR_SCHEMA;
			}
		}
	}
	if (is_self_key(key)) {
		if (values->count > MAX_SELF_VALUES) {
			return ODE_ATTR_SCHEMA;
		}
		for (i = 0; i < values->count; i++) {
			if (values->items[i]->len > MAX_SELF_VALUE) {
				return ODE_ATTR_SCHEMA;
			}
		}
	}
	if (strcmp(key, "name") == 0) {
		if (values->count == 0) {
			return ODE_PARAMETER;
		}
		for (i = 0; i < values->count; i++) {
			if (!store_valid_name(pl_str(values->items[i]))) {
				return ODE_PARAMETER;
			}
		}
	}
	return 0;
}

static uint64_t
may_write(struct call *c, const struct ident *id, enum rtype t, const pl_t *rec, const char *key,
    const pl_t *values)
{
	if (c->node->search) {
		return ODE_READ_ONLY_NODE;
	}
	if (id->admin) {
		return 0;
	}
	if (t == RT_USERS && is_self(id, rec) && is_self_key(key)) {
		if (strcmp(key, "shell") == 0 && !shell_allowed(c, rec, values)) {
			return ODE_PERMISSION;
		}
		return 0;
	}
	return ODE_PERMISSION;
}

static uint64_t
names_free(struct call *c, enum rtype t, const pl_t *rec, const pl_t *names)
{
	const pl_t *other;
	size_t i;

	for (i = 0; i < names->count; i++) {
		other = store_find(&c->od->store, t, pl_str(names->items[i]));
		if (other != NULL && other != rec) {
			return ODE_ALREADY_EXISTS;
		}
	}
	return 0;
}

static uint64_t
write_record(struct call *c, enum rtype t, const pl_t *orig, pl_t *rec, const char *what,
    const char *attr)
{
	char fname[256], name[256];
	uint64_t err;

	if (!store_file_name(&c->od->store, t, orig, fname, sizeof(fname))) {
		pl_free(rec);
		return ODE_NO_LONGER_EXISTS;
	}
	if (store_write(&c->od->store, t, rec, fname) != 0) {
		err = write_error();
		c->od->log(OD_LOG_ERR, "cannot write %s %s: %s", t == RT_USERS ? "user" : "group",
		    rec_name(rec), strerror(errno));
		pl_free(rec);
		return err;
	}
	snprintf(name, sizeof(name), "%s", rec_name(rec));
	pl_free(rec);
	changed(c, what, t, name, attr);
	return 0;
}

static void
fn_modify(struct call *c)
{
	const char *attr = param_str(c, 3), *key;
	const pl_t *rec, *arg = param(c, 4), *cur;
	pl_t *values = NULL, *copy;
	struct ident id;
	bool known, set = strcmp(c->fn, "ODRecordSetValue") == 0;
	bool add = strcmp(c->fn, "ODRecordAddValue") == 0;
	enum rtype t;
	uint64_t err;
	size_t i;

	err = lookup_record(c, &t, &rec);
	if (err == 0 && attr == NULL) {
		err = ODE_PARAMETER;
	}
	if (err == 0 && attr_is_virtual(attr)) {
		err = ODE_PERMISSION;
	}
	if (err == 0) {
		key = attr_key(attr, &known);
		if (!known) {
			err = ODE_ATTR_UNKNOWN_TYPE;
		}
	}
	if (err != 0) {
		reply_error(c, err, 1, NULL);
		return;
	}
	if (set && pl_is(arg, PL_ARRAY)) {
		values = pl_copy(arg);
	} else if (pl_is(arg, PL_STRING) || pl_is(arg, PL_DATA)) {
		values = pl_array();
		pl_array_append(values, pl_copy(arg));
	} else {
		reply_error(c, ODE_PARAMETER, 1, NULL);
		return;
	}
	ident_of(c, &id);
	if (set && strcmp(key, "passwd") == 0 && t == RT_USERS) {
		const char *pw = pl_str(pl_array_get(values, 0));

		if (values->count == 1 && pw != NULL && strcmp(pw, OD_HIDDEN_PASSWORD) == 0) {
			err = 0;
		} else if (values->count != 1 || pw == NULL || pw[0] == '\0' || strlen(pw) > MAX_PASSWORD) {
			err = ODE_PASSWORD_QUALITY;
		} else if (c->node->search) {
			err = ODE_READ_ONLY_NODE;
		} else if (!id.admin) {
			err = ODE_CRED_NOT_AUTHORIZED;
		} else {
			err = set_password(c, rec, pw);
		}
		pl_free(values);
		reply_error(c, err, 1, NULL);
		return;
	}
	if (strcmp(key, "passwd") == 0) {
		pl_free(values);
		reply_error(c, ODE_PERMISSION, 1, NULL);
		return;
	}
	copy = pl_copy(rec);
	cur = pl_dict_get(copy, key);
	if (set) {
		if (values->count == 0) {
			if (strcmp(key, "name") == 0) {
				err = ODE_PARAMETER;
			} else if (cur == NULL) {
				err = ODE_ATTR_UNKNOWN_TYPE;
			} else {
				pl_dict_remove(copy, key);
			}
		} else {
			pl_dict_set(copy, key, pl_copy(values));
		}
	} else if (add) {
		pl_t *a = pl_dict_get(copy, key);

		if (a == NULL) {
			a = pl_array();
			pl_dict_set(copy, key, a);
		}
		for (i = 0; i < a->count && !pl_equal(a->items[i], values->items[0]); i++) {
		}
		if (i == a->count) {
			pl_array_append(a, pl_copy(values->items[0]));
		}
	} else {
		pl_t *a = pl_dict_get(copy, key);

		for (i = 0; a != NULL && i < a->count && !pl_equal(a->items[i], values->items[0]); i++) {
		}
		if (a == NULL || i == a->count) {
			err = ODE_ATTR_VALUE_NOT_FOUND;
		} else {
			pl_array_remove(a, i);
			if (a->count == 0) {
				if (strcmp(key, "name") == 0) {
					err = ODE_PARAMETER;
				} else {
					pl_dict_remove(copy, key);
				}
			}
		}
	}
	if (err == 0) {
		cur = pl_dict_get(copy, key);
		err = may_write(c, &id, t, rec, key, cur != NULL ? cur : values);
	}
	if (err == 0 && cur != NULL) {
		err = check_values(key, cur);
	}
	if (err == 0 && strcmp(key, "name") == 0) {
		err = names_free(c, t, rec, cur);
	}
	pl_free(values);
	if (err != 0) {
		pl_free(copy);
		reply_error(c, err, 1, NULL);
		return;
	}
	reply_error(c, write_record(c, t, rec, copy, set ? "set" : add ? "added to" : "removed from",
	    attr), 1, NULL);
}

static void
fn_delete(struct call *c)
{
	const pl_t *rec;
	struct ident id;
	char fname[256], name[256];
	enum rtype t;
	uint64_t err;

	err = lookup_record(c, &t, &rec);
	if (err == 0) {
		ident_of(c, &id);
		if (c->node->search) {
			err = ODE_READ_ONLY_NODE;
		} else if (!id.admin) {
			err = ODE_PERMISSION;
		}
	}
	if (err == 0) {
		snprintf(name, sizeof(name), "%s", rec_name(rec));
		if (!store_file_name(&c->od->store, t, rec, fname, sizeof(fname)) ||
		    store_delete(&c->od->store, t, fname) != 0) {
			c->od->log(OD_LOG_ERR, "cannot delete %s: %s", name, strerror(errno));
			err = ODE_PLUGIN;
		} else {
			changed(c, "deleted", t, name, NULL);
		}
	}
	reply_error(c, err, 1, NULL);
}

static void
fn_create_record(struct call *c)
{
	const char *name = param_str(c, 1), *key;
	const pl_t *attrs = param(c, 2);
	struct ident id;
	pl_t *rec, *names;
	uint8_t uu[16];
	char text[37];
	enum rtype t;
	uint64_t err = 0;
	bool known;
	size_t i;

	if (rtype_from_name(param_str(c, 0), &t) != 0) {
		reply_error(c, ODE_INVALID_TYPE, 0, NULL);
		return;
	}
	if (!store_valid_name(name) || (attrs != NULL && !pl_is(attrs, PL_DICT))) {
		reply_error(c, ODE_PARAMETER, 0, NULL);
		return;
	}
	ident_of(c, &id);
	if (c->node->search) {
		reply_error(c, ODE_READ_ONLY_NODE, 0, NULL);
		return;
	}
	if (!id.admin) {
		c->od->log(OD_LOG_WARNING, "uid %u (pid %d) may not create %s", (unsigned)id.euid,
		    (int)c->caller->pid, name);
		reply_error(c, ODE_PERMISSION, 0, NULL);
		return;
	}
	if (store_find(&c->od->store, t, name) != NULL) {
		reply_error(c, ODE_ALREADY_EXISTS, 0, NULL);
		return;
	}
	rec = pl_dict();
	names = string_array(name);
	for (i = 0; attrs != NULL && i < attrs->count && err == 0; i++) {
		if (attr_is_virtual(attrs->keys[i])) {
			continue;
		}
		key = attr_key(attrs->keys[i], &known);
		if (!known) {
			err = ODE_ATTR_UNKNOWN_TYPE;
		} else if (!pl_is(attrs->items[i], PL_ARRAY) || strcmp(key, "passwd") == 0) {
			err = strcmp(key, "passwd") == 0 ? 0 : ODE_ATTR_SCHEMA;
		} else if (strcmp(key, "name") == 0) {
			size_t j;

			for (j = 0; j < attrs->items[i]->count; j++) {
				size_t k;

				for (k = 0; k < names->count &&
				    !pl_equal(attrs->items[i]->items[j], names->items[k]); k++) {
				}
				if (k == names->count) {
					pl_array_append(names, pl_copy(attrs->items[i]->items[j]));
				}
			}
		} else if (attrs->items[i]->count > 0) {
			err = check_values(key, attrs->items[i]);
			if (err == 0) {
				pl_dict_set(rec, key, pl_copy(attrs->items[i]));
			}
		}
	}
	if (err == 0) {
		err = check_values("name", names);
	}
	if (err == 0) {
		err = names_free(c, t, NULL, names);
	}
	if (err != 0) {
		pl_free(names);
		pl_free(rec);
		reply_error(c, err, 0, NULL);
		return;
	}
	pl_dict_set(rec, "name", names);
	if (pl_dict_get(rec, "generateduid") == NULL) {
		uuid_random(uu);
		uuid_text(uu, text);
		pl_dict_set(rec, "generateduid", string_array(text));
	}
	if (store_write(&c->od->store, t, rec, NULL) != 0) {
		err = write_error();
		c->od->log(OD_LOG_ERR, "cannot create %s: %s", name, strerror(errno));
		pl_free(rec);
		reply_error(c, err, 0, NULL);
		return;
	}
	changed(c, "created", t, name, NULL);
	{
		pl_t *all = pl_array();

		pl_array_append(all, pl_string(OD_ATTR_ALL));
		reply(c, 0, results(2, NULL, export_record(c, t, rec, all, false)));
		pl_free(all);
	}
	pl_free(rec);
}

static void
fn_ok(struct call *c)
{
	reply(c, 0, NULL);
}

static void
fn_query_sync(struct call *c)
{
	reply(c, ODE_QUERY_INVALID, NULL);
}

struct handler {
	const char *name;
	bool node;
	void (*fn)(struct call *c);
};

static const struct handler handlers[] = {
	{ "ODSessionRelease", false, fn_ok },
	{ "ODSessionCopyNodeNames", false, fn_node_names },
	{ "ODNodeCreateWithName", false, fn_node_create },
	{ "ODNodeRelease", false, fn_node_release },
	{ "ODNodeCopySubnodeNames", true, fn_subnodes },
	{ "ODNodeCopyUnreachableSubnodeNames", true, fn_unreachable },
	{ "ODNodeSetCredentials", true, fn_set_credentials },
	{ "ODNodeCreateRecord", true, fn_create_record },
	{ "ODQueryCreateWithNode", true, fn_query },
	{ "ODQueryCancel", false, fn_ok },
	{ "ODQuerySynchronize", false, fn_query_sync },
	{ "ODContextRelease", false, fn_ok },
	{ "ODRecordVerifyPassword", true, fn_verify },
	{ "ODRecordAuthenticationAllowed", true, fn_auth_allowed },
	{ "ODRecordChangePassword", true, fn_change_password },
	{ "ODRecordSetValue", true, fn_modify },
	{ "ODRecordAddValue", true, fn_modify },
	{ "ODRecordRemoveValue", true, fn_modify },
	{ "ODRecordDelete", true, fn_delete },
};

static bool
is_zero(const uint8_t uu[16])
{
	static const uint8_t zero[16];

	return memcmp(uu, zero, 16) == 0;
}

void
od_api(struct od *od, const struct od_caller *caller, const uint8_t session[16],
    const uint8_t node[16], const uint8_t *data, size_t len, od_send_t send, void *ctx)
{
	struct call c = { od, caller, NULL, NULL, NULL, send, ctx };
	const struct handler *h = NULL;
	pl_t *req;
	size_t i;

	store_refresh(&od->store, RT_USERS);
	store_refresh(&od->store, RT_GROUPS);
	req = NULL;
	if (len > MAX_REQUEST) {
		od->log(OD_LOG_WARNING, "request of %zu bytes refused (pid %d, uid %u)", len, (int)caller->pid,
		    (unsigned)caller->euid);
	} else {
		req = pl_bplist_read(data, len);
	}
	c.fn = pl_str(pl_dict_get(req, "funcname"));
	c.params = pl_dict_get(req, "parameters");
	if (c.fn == NULL || (c.params != NULL && !pl_is(c.params, PL_ARRAY))) {
		c.fn = "";
		c.params = NULL;
		reply(&c, ODE_PARAMETER, NULL);
		pl_free(req);
		return;
	}
	for (i = 0; i < sizeof(handlers) / sizeof(handlers[0]); i++) {
		if (strcmp(handlers[i].name, c.fn) == 0) {
			h = &handlers[i];
		}
	}
	if (!is_zero(session) && strcmp(c.fn, "ODSessionRelease") != 0) {
		reply_error(&c, ODE_SESSION_INVALID, 1, NULL);
	} else if (h == NULL) {
		reply(&c, ODE_NOT_SUPPORTED, NULL);
	} else if (h->node && (c.node = find_node(od, node, caller->peer)) == NULL) {
		reply_error(&c, ODE_NODE_INVALID, 1, NULL);
	} else {
		if (!h->node && !is_zero(node)) {
			c.node = find_node(od, node, caller->peer);
		}
		h->fn(&c);
	}
	pl_free(req);
}

int
od_init(struct od *od, const char *root)
{
	return store_init(&od->store, root);
}

void
od_free(struct od *od)
{
	struct node *n;

	while ((n = od->nodes) != NULL) {
		od->nodes = n->next;
		free_node(n);
	}
	backoff_free(od);
	store_free(&od->store);
}
