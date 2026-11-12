/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 The Blueberry Pie OS Authors
 */
#include <sys/types.h>
#include <sys/kauth.h>

#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include "od.h"

#define WANT_MASK (KAUTH_EXTLOOKUP_WANT_UID | KAUTH_EXTLOOKUP_WANT_UGUID | KAUTH_EXTLOOKUP_WANT_USID | \
	KAUTH_EXTLOOKUP_WANT_GID | KAUTH_EXTLOOKUP_WANT_GGUID | KAUTH_EXTLOOKUP_WANT_GSID | \
	KAUTH_EXTLOOKUP_WANT_MEMBERSHIP | KAUTH_EXTLOOKUP_WANT_PWNAM | KAUTH_EXTLOOKUP_WANT_GRNAM | \
	KAUTH_EXTLOOKUP_WANT_SUPGRPS)
#define MAX_SUPGRPS (sizeof(((struct kauth_identity_extlookup *)0)->el_sup_groups) / sizeof(gid_t))

struct who {
	enum rtype t;
	const pl_t *rec;
	uint32_t id;
	bool found;
};

static bool
number(const char **p, unsigned long long max, unsigned long long *v)
{
	const char *s = *p;

	*v = 0;
	if (*s < '0' || *s > '9') {
		return false;
	}
	for (; *s >= '0' && *s <= '9'; s++) {
		if (*v > (max - (unsigned long long)(*s - '0')) / 10) {
			return false;
		}
		*v = *v * 10 + (unsigned long long)(*s - '0');
	}
	*p = s;
	return true;
}

static bool
sid_parse(const char *s, ntsid_t *sid)
{
	unsigned long long v;
	int i;

	memset(sid, 0, sizeof(*sid));
	if (s == NULL || s[0] != 'S' || s[1] != '-') {
		return false;
	}
	s += 2;
	if (!number(&s, 255, &v) || *s++ != '-') {
		return false;
	}
	sid->sid_kind = (u_int8_t)v;
	if (!number(&s, 0xffffffffffffULL, &v)) {
		return false;
	}
	for (i = 5; i >= 0; i--) {
		sid->sid_authority[i] = (u_int8_t)v;
		v >>= 8;
	}
	while (*s == '-') {
		s++;
		if (sid->sid_authcount == KAUTH_NTSID_MAX_AUTHORITIES || !number(&s, UINT32_MAX, &v)) {
			return false;
		}
		sid->sid_authorities[sid->sid_authcount++] = (u_int32_t)v;
	}
	return *s == '\0';
}

static bool
sid_equal(const ntsid_t *a, const ntsid_t *b)
{
	return a->sid_kind == b->sid_kind && a->sid_authcount == b->sid_authcount &&
	    a->sid_authcount <= KAUTH_NTSID_MAX_AUTHORITIES && memcmp(a, b, KAUTH_NTSID_SIZE(a)) == 0;
}

static bool
rec_sid(const pl_t *rec, ntsid_t *sid)
{
	return rec != NULL && sid_parse(rec_first(rec, "smb_sid"), sid);
}

static const char *
id_key(enum rtype t)
{
	return t == RT_USERS ? "uid" : "gid";
}

static void
by_id(struct od *od, struct who *w, uint32_t id)
{
	w->rec = store_find_id(&od->store, w->t, id_key(w->t), id);
	w->id = id;
	w->found = true;
}

static void
by_rec(struct who *w, const pl_t *rec)
{
	w->rec = rec;
	w->found = rec != NULL && rec_id(rec, id_key(w->t), &w->id);
}

static void
by_uuid(struct od *od, struct who *w, const guid_t *guid)
{
	enum rtype t;
	uint32_t id;

	by_rec(w, od_find_uuid(od, w->t, guid->g_guid));
	if (!w->found && od_parse_compat(guid->g_guid, &t, &id) && t == w->t) {
		by_id(od, w, id);
	}
}

static void
by_sid(struct od *od, struct who *w, const ntsid_t *sid)
{
	ntsid_t v;
	size_t i;

	for (i = 0; i < store_count(&od->store, w->t); i++) {
		if (rec_sid(store_rec(&od->store, w->t, i), &v) && sid_equal(&v, sid)) {
			by_rec(w, store_rec(&od->store, w->t, i));
			if (w->found) {
				return;
			}
		}
	}
}

static bool
is_member(struct od *od, const struct who *u, const struct who *g)
{
	uint32_t gid;

	if (u->rec == NULL) {
		return false;
	}
	if (g->id == OD_EVERYONE_GID) {
		return true;
	}
	if (g->rec == NULL) {
		return rec_id(u->rec, "gid", &gid) && gid == g->id;
	}
	return od_is_member(od, u->rec, g->rec);
}

static bool
listed(const gid_t *list, size_t n, gid_t gid)
{
	size_t i;

	for (i = 0; i < n; i++) {
		if (list[i] == gid) {
			return true;
		}
	}
	return false;
}

static bool
in_groups(const pl_t *groups, gid_t gid)
{
	size_t i;

	for (i = 0; i < groups->count; i++) {
		if ((gid_t)groups->items[i]->i == gid) {
			return true;
		}
	}
	return false;
}

static void
supgroups(struct od *od, struct kauth_identity_extlookup *el, const pl_t *user, bool keep)
{
	pl_t *all = od_user_groups(od, user, 65536);
	size_t i, n = 0, prev = keep ? el->el_sup_grp_cnt : 0;
	gid_t now[MAX_SUPGRPS], gid;

	if (prev > MAX_SUPGRPS) {
		prev = MAX_SUPGRPS;
	}
	for (i = 0; i < prev; i++) {
		gid = el->el_sup_groups[i];
		if (in_groups(all, gid) && !listed(now, n, gid)) {
			now[n++] = gid;
		}
	}
	for (i = 0; i < all->count && n < MAX_SUPGRPS; i++) {
		gid = (gid_t)all->items[i]->i;
		if (!listed(now, n, gid)) {
			now[n++] = gid;
		}
	}
	pl_free(all);
	memset(el->el_sup_groups, 0, sizeof(el->el_sup_groups));
	memcpy(el->el_sup_groups, now, n * sizeof(now[0]));
	el->el_sup_grp_cnt = (u_int32_t)n;
}

static bool
put_name(struct kauth_identity_extlookup *el, const pl_t *rec, char *out, size_t outsize)
{
	const char *name = rec_first(rec, "name");
	size_t len;

	if (name == NULL || out == NULL || (len = strlen(name)) >= outsize) {
		return false;
	}
	memcpy(out, name, len + 1);
	el->el_extend = (u_int64_t)(uintptr_t)out;
	return true;
}

void
od_resolve(struct od *od, struct kauth_identity_extlookup *el, const char *name, char *out,
    size_t outsize)
{
	u_int32_t in = el->el_flags, flags = in & WANT_MASK;
	struct who u = { RT_USERS, NULL, 0, false }, g = { RT_GROUPS, NULL, 0, false };
	bool named = false;
	ntsid_t sid;
	uint8_t uu[16];

	store_refresh(&od->store, RT_USERS);
	store_refresh(&od->store, RT_GROUPS);
	if (in & (KAUTH_EXTLOOKUP_VALID_UID | KAUTH_EXTLOOKUP_VALID_GID)) {
		if (in & KAUTH_EXTLOOKUP_VALID_UID) {
			by_id(od, &u, el->el_uid);
		}
		if (in & KAUTH_EXTLOOKUP_VALID_GID) {
			by_id(od, &g, el->el_gid);
		}
	} else if (in & (KAUTH_EXTLOOKUP_VALID_UGUID | KAUTH_EXTLOOKUP_VALID_GGUID)) {
		if (in & KAUTH_EXTLOOKUP_VALID_UGUID) {
			by_uuid(od, &u, &el->el_uguid);
		}
		if (!u.found && (in & KAUTH_EXTLOOKUP_VALID_GGUID)) {
			by_uuid(od, &g, &el->el_gguid);
		}
	} else if (in & (KAUTH_EXTLOOKUP_VALID_USID | KAUTH_EXTLOOKUP_VALID_GSID)) {
		if (in & KAUTH_EXTLOOKUP_VALID_USID) {
			by_sid(od, &u, &el->el_usid);
		}
		if (!u.found && (in & KAUTH_EXTLOOKUP_VALID_GSID)) {
			by_sid(od, &g, &el->el_gsid);
		}
	} else if ((in & (KAUTH_EXTLOOKUP_VALID_PWNAM | KAUTH_EXTLOOKUP_VALID_GRNAM)) && name != NULL &&
	    name[0] != '\0') {
		if (in & KAUTH_EXTLOOKUP_VALID_PWNAM) {
			by_rec(&u, store_find(&od->store, RT_USERS, name));
		}
		if (!u.found && (in & KAUTH_EXTLOOKUP_VALID_GRNAM)) {
			by_rec(&g, store_find(&od->store, RT_GROUPS, name));
		}
	} else {
		el->el_flags = flags;
		el->el_result = KAUTH_EXTLOOKUP_BADRQ;
		return;
	}
	if (u.found) {
		flags |= KAUTH_EXTLOOKUP_VALID_UID;
		el->el_uid = u.id;
		if (in & KAUTH_EXTLOOKUP_WANT_UGUID) {
			if (u.rec == NULL || !od_rec_uuid(u.rec, RT_USERS, uu)) {
				od_compat_uuid(RT_USERS, u.id, uu);
			}
			memcpy(el->el_uguid.g_guid, uu, 16);
			flags |= KAUTH_EXTLOOKUP_VALID_UGUID;
		}
		if ((in & KAUTH_EXTLOOKUP_WANT_USID) && rec_sid(u.rec, &sid)) {
			el->el_usid = sid;
			flags |= KAUTH_EXTLOOKUP_VALID_USID;
		}
		if ((in & KAUTH_EXTLOOKUP_WANT_PWNAM) && u.rec != NULL && put_name(el, u.rec, out, outsize)) {
			flags |= KAUTH_EXTLOOKUP_VALID_PWNAM;
			named = true;
		}
		if ((in & KAUTH_EXTLOOKUP_WANT_SUPGRPS) && u.rec != NULL) {
			supgroups(od, el, u.rec, (in & KAUTH_EXTLOOKUP_VALID_SUPGRPS) != 0);
			flags |= KAUTH_EXTLOOKUP_VALID_SUPGRPS;
		}
	}
	if (g.found) {
		flags |= KAUTH_EXTLOOKUP_VALID_GID;
		el->el_gid = g.id;
		if (in & KAUTH_EXTLOOKUP_WANT_GGUID) {
			if (g.rec == NULL || !od_rec_uuid(g.rec, RT_GROUPS, uu)) {
				od_compat_uuid(RT_GROUPS, g.id, uu);
			}
			memcpy(el->el_gguid.g_guid, uu, 16);
			flags |= KAUTH_EXTLOOKUP_VALID_GGUID;
		}
		if ((in & KAUTH_EXTLOOKUP_WANT_GSID) && rec_sid(g.rec, &sid)) {
			el->el_gsid = sid;
			flags |= KAUTH_EXTLOOKUP_VALID_GSID;
		}
		if ((in & KAUTH_EXTLOOKUP_WANT_GRNAM) && !named && g.rec != NULL &&
		    put_name(el, g.rec, out, outsize)) {
			flags |= KAUTH_EXTLOOKUP_VALID_GRNAM;
		}
	}
	if ((in & KAUTH_EXTLOOKUP_WANT_MEMBERSHIP) && u.found && g.found) {
		flags |= KAUTH_EXTLOOKUP_VALID_MEMBERSHIP;
		if (is_member(od, &u, &g)) {
			flags |= KAUTH_EXTLOOKUP_ISMEMBER;
		}
	}
	el->el_uguid_valid = OD_RESOLVER_TTL;
	el->el_usid_valid = OD_RESOLVER_TTL;
	el->el_gguid_valid = OD_RESOLVER_TTL;
	el->el_gsid_valid = OD_RESOLVER_TTL;
	el->el_member_valid = OD_RESOLVER_TTL;
	el->el_flags = flags;
	el->el_result = KAUTH_EXTLOOKUP_SUCCESS;
}

static int
enroll(struct od_resolver *r)
{
	if (r->svc(KAUTH_EXTLOOKUP_REGISTER, NULL) != 0) {
		r->od->log(OD_LOG_ERR, "cannot register as the identity resolver: %s", strerror(errno));
		return -1;
	}
	atomic_store(&r->up, true);
	if (atomic_load(&r->stopped)) {
		if (atomic_exchange(&r->up, false)) {
			r->svc(KAUTH_EXTLOOKUP_DEREGISTER, NULL);
		}
		return 1;
	}
	r->svc(KAUTH_CLEAR_CACHES, NULL);
	r->od->log(OD_LOG_NOTICE, "registered as the identity resolver");
	return 0;
}

int
od_resolver_run(struct od_resolver *r)
{
	struct kauth_identity_extlookup el;
	char in[PATH_MAX], out[PATH_MAX];
	unsigned gen, failures = 0;
	int e;

	r->od->store.shared_gen = &r->gen;
	if ((e = enroll(r)) != 0) {
		return e > 0 ? 0 : -1;
	}
	for (;;) {
		memset(&el, 0, sizeof(el));
		memset(in, 0, sizeof(in));
		el.el_extend = (u_int64_t)(uintptr_t)in;
		if (r->svc(KAUTH_EXTLOOKUP_WORKER, &el) != 0) {
			e = errno;
			if (atomic_load(&r->stopped)) {
				return 0;
			}
			if (e == EINTR) {
				continue;
			}
			atomic_store(&r->up, false);
			r->od->log(OD_LOG_WARNING, "identity requests failed: %s", strerror(e));
			if (++failures > OD_RESOLVER_RETRIES) {
				r->od->log(OD_LOG_ERR, "no longer the identity resolver");
				return -1;
			}
			r->pause();
			if (atomic_load(&r->stopped)) {
				return 0;
			}
			if ((e = enroll(r)) != 0) {
				return e > 0 ? 0 : -1;
			}
			continue;
		}
		failures = 0;
		gen = atomic_load(&r->gen);
		in[sizeof(in) - 1] = '\0';
		od_resolve(r->od, &el, in, out, sizeof(out));
		if (r->svc(KAUTH_EXTLOOKUP_RESULT, &el) != 0) {
			r->od->log(OD_LOG_WARNING, "identity answer %u not taken: %s", (unsigned)el.el_seqno,
			    strerror(errno));
		}
		if (atomic_load(&r->gen) != gen) {
			r->svc(KAUTH_CLEAR_CACHES, NULL);
		}
	}
}

void
od_resolver_changed(struct od_resolver *r)
{
	atomic_fetch_add(&r->gen, 1);
	if (atomic_load(&r->up)) {
		r->svc(KAUTH_CLEAR_CACHES, NULL);
	}
}

void
od_resolver_clear(struct od_resolver *r)
{
	if (atomic_load(&r->up)) {
		r->svc(KAUTH_CLEAR_CACHES, NULL);
	}
}

void
od_resolver_stop(struct od_resolver *r)
{
	atomic_store(&r->stopped, true);
	if (atomic_exchange(&r->up, false)) {
		r->svc(KAUTH_EXTLOOKUP_DEREGISTER, NULL);
	}
}
