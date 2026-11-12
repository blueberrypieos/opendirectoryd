/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 The Blueberry Pie OS Authors
 */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "od.h"

#define ID_TYPE_UID 0
#define ID_TYPE_GID 1
#define ID_TYPE_SID 3
#define ID_TYPE_USERNAME 4
#define ID_TYPE_GROUPNAME 5
#define ID_TYPE_UUID 6
#define ID_TYPE_GROUP_NFS 7
#define ID_TYPE_USER_NFS 8
#define ID_TYPE_UID_OR_GID 30
#define ID_TYPE_NAME 31
#define MBR_REC_TYPE_USER 1
#define MBR_REC_TYPE_GROUP 2
#define MAX_NESTING 8

static const uint8_t user_prefix[12] = { 0xff, 0xff, 0xee, 0xee, 0xdd, 0xdd, 0xcc, 0xcc, 0xbb, 0xbb,
	0xaa, 0xaa };
static const uint8_t group_prefix[12] = { 0xab, 0xcd, 0xef, 0xab, 0xcd, 0xef, 0xab, 0xcd, 0xef, 0xab,
	0xcd, 0xef };

static void
compat_uuid(int rectype, uint32_t id, uint8_t uu[16])
{
	memcpy(uu, rectype == MBR_REC_TYPE_USER ? user_prefix : group_prefix, 12);
	uu[12] = (uint8_t)(id >> 24);
	uu[13] = (uint8_t)(id >> 16);
	uu[14] = (uint8_t)(id >> 8);
	uu[15] = (uint8_t)id;
}

static bool
parse_compat(const uint8_t uu[16], int *rectype, uint32_t *id)
{
	if (memcmp(uu, user_prefix, 12) == 0) {
		*rectype = MBR_REC_TYPE_USER;
	} else if (memcmp(uu, group_prefix, 12) == 0) {
		*rectype = MBR_REC_TYPE_GROUP;
	} else {
		return false;
	}
	*id = (uint32_t)uu[12] << 24 | (uint32_t)uu[13] << 16 | (uint32_t)uu[14] << 8 | uu[15];
	return true;
}

static bool
rec_uuid(const pl_t *rec, int rectype, uint8_t uu[16])
{
	uint32_t id;

	if (uuid_parse_text(rec_first(rec, "generateduid"), uu)) {
		return true;
	}
	if (rec_id(rec, rectype == MBR_REC_TYPE_USER ? "uid" : "gid", &id)) {
		compat_uuid(rectype, id, uu);
		return true;
	}
	return false;
}

static const pl_t *
find_uuid(struct od *od, enum rtype t, const uint8_t uu[16])
{
	uint8_t v[16];
	size_t i;
	const pl_t *rec;

	for (i = 0; i < store_count(&od->store, t); i++) {
		rec = store_rec(&od->store, t, i);
		if (rec != NULL && uuid_parse_text(rec_first(rec, "generateduid"), v) &&
		    memcmp(v, uu, 16) == 0) {
			return rec;
		}
	}
	return NULL;
}

static bool
values_have_uuid(const pl_t *rec, const char *key, const uint8_t uu[16])
{
	const pl_t *a = pl_dict_get(rec, key);
	uint8_t v[16];
	size_t i;

	for (i = 0; a != NULL && i < a->count; i++) {
		if (uuid_parse_text(pl_str(a->items[i]), v) && memcmp(v, uu, 16) == 0) {
			return true;
		}
	}
	return false;
}

static bool
contains(struct od *od, const pl_t *user, const pl_t *group, int depth)
{
	const pl_t *names = pl_dict_get(user, "name"), *nested, *g;
	uint32_t ugid, ggid;
	uint8_t uu[16], nu[16];
	size_t i;

	if (rec_id(group, "gid", &ggid)) {
		if (ggid == OD_EVERYONE_GID) {
			return true;
		}
		if (rec_id(user, "gid", &ugid) && ugid == ggid) {
			return true;
		}
	}
	for (i = 0; names != NULL && i < names->count; i++) {
		if (pl_str(names->items[i]) != NULL && rec_has(group, "users", pl_str(names->items[i]))) {
			return true;
		}
	}
	if (rec_uuid(user, MBR_REC_TYPE_USER, uu) && values_have_uuid(group, "groupmembers", uu)) {
		return true;
	}
	if (depth >= MAX_NESTING) {
		return false;
	}
	nested = pl_dict_get(group, "nestedgroups");
	for (i = 0; nested != NULL && i < nested->count; i++) {
		if (!uuid_parse_text(pl_str(nested->items[i]), nu)) {
			continue;
		}
		g = find_uuid(od, RT_GROUPS, nu);
		if (g != NULL && g != group && contains(od, user, g, depth + 1)) {
			return true;
		}
	}
	return false;
}

void
od_compat_uuid(enum rtype t, uint32_t id, uint8_t uu[16])
{
	compat_uuid(t == RT_USERS ? MBR_REC_TYPE_USER : MBR_REC_TYPE_GROUP, id, uu);
}

bool
od_parse_compat(const uint8_t uu[16], enum rtype *t, uint32_t *id)
{
	int rectype;

	if (!parse_compat(uu, &rectype, id)) {
		return false;
	}
	*t = rectype == MBR_REC_TYPE_USER ? RT_USERS : RT_GROUPS;
	return true;
}

bool
od_rec_uuid(const pl_t *rec, enum rtype t, uint8_t uu[16])
{
	return rec_uuid(rec, t == RT_USERS ? MBR_REC_TYPE_USER : MBR_REC_TYPE_GROUP, uu);
}

const pl_t *
od_find_uuid(struct od *od, enum rtype t, const uint8_t uu[16])
{
	return find_uuid(od, t, uu);
}

bool
od_is_member(struct od *od, const pl_t *user, const pl_t *group)
{
	return user != NULL && group != NULL && contains(od, user, group, 0);
}

bool
od_user_is_admin(struct od *od, const pl_t *user)
{
	uint32_t uid;

	if (user == NULL) {
		return false;
	}
	if (rec_id(user, "uid", &uid) && uid == 0) {
		return true;
	}
	return od_is_member(od, user, store_find(&od->store, RT_GROUPS, OD_ADMIN_GROUP));
}

pl_t *
od_user_groups(struct od *od, const pl_t *user, uint32_t max)
{
	pl_t *list = pl_array();
	uint32_t gid, primary;
	bool have_primary = rec_id(user, "gid", &primary);
	const pl_t *g;
	size_t i;

	if (have_primary && max > 0) {
		pl_array_append(list, pl_int(primary));
	}
	for (i = 0; i < store_count(&od->store, RT_GROUPS) && list->count < max; i++) {
		g = store_rec(&od->store, RT_GROUPS, i);
		if (g == NULL || !rec_id(g, "gid", &gid) || (have_primary && gid == primary)) {
			continue;
		}
		if (contains(od, user, g, 0)) {
			size_t j;
			bool dup = false;

			for (j = 0; j < list->count; j++) {
				if ((uint32_t)list->items[j]->i == gid) {
					dup = true;
				}
			}
			if (!dup) {
				pl_array_append(list, pl_int(gid));
			}
		}
	}
	return list;
}

static void
set_str(pl_t *d, const char *key, const char *v)
{
	pl_dict_set(d, key, pl_string(v));
}

static pl_t *
user_entry(const pl_t *rec)
{
	uint32_t uid, gid;
	const char *s;
	pl_t *d;

	if (rec == NULL || !rec_id(rec, "uid", &uid) || !rec_id(rec, "gid", &gid)) {
		return NULL;
	}
	d = pl_dict();
	set_str(d, "pw_name", rec_first(rec, "name"));
	set_str(d, "pw_passwd", OD_HIDDEN_PASSWORD);
	pl_dict_set(d, "pw_uid", pl_int(uid));
	pl_dict_set(d, "pw_gid", pl_int(gid));
	pl_dict_set(d, "pw_change", pl_int(0));
	pl_dict_set(d, "pw_expire", pl_int(0));
	set_str(d, "pw_class", "");
	set_str(d, "pw_gecos", (s = rec_first(rec, "realname")) ? s : "");
	set_str(d, "pw_dir", (s = rec_first(rec, "home")) ? s : "/var/empty");
	set_str(d, "pw_shell", (s = rec_first(rec, "shell")) ? s : "/usr/bin/false");
	return d;
}

static pl_t *
group_entry(const pl_t *rec)
{
	const pl_t *users;
	uint32_t gid;
	pl_t *d, *mem;
	size_t i;

	if (rec == NULL || !rec_id(rec, "gid", &gid)) {
		return NULL;
	}
	d = pl_dict();
	set_str(d, "gr_name", rec_first(rec, "name"));
	set_str(d, "gr_passwd", "*");
	pl_dict_set(d, "gr_gid", pl_int(gid));
	mem = pl_array();
	users = pl_dict_get(rec, "users");
	for (i = 0; users != NULL && i < users->count; i++) {
		if (pl_str(users->items[i]) != NULL) {
			pl_array_append(mem, pl_copy(users->items[i]));
		}
	}
	pl_dict_set(d, "gr_mem", mem);
	return d;
}

static pl_t *
with_error(pl_t *d, int64_t error)
{
	if (d == NULL) {
		d = pl_dict();
	}
	pl_dict_set(d, "error", pl_int(error));
	return d;
}

static pl_t *
item_reply(pl_t *entry)
{
	return entry != NULL ? with_error(entry, 0) : with_error(NULL, ENOENT);
}

static bool
req_id(const pl_t *req, const char *key, uint32_t *id)
{
	const pl_t *v = pl_dict_get(req, key);

	if (!pl_is(v, PL_INT)) {
		return false;
	}
	*id = (uint32_t)v->i;
	return true;
}

static const uint8_t *
req_uuid(const pl_t *req, const char *key)
{
	const pl_t *v = pl_dict_get(req, key);

	return (pl_is(v, PL_DATA) && v->len == 16) ? v->bytes : NULL;
}

static const pl_t *
user_by_uuid(struct od *od, const uint8_t *uu)
{
	const pl_t *rec;
	uint32_t id;
	int type;

	if (uu == NULL) {
		return NULL;
	}
	if ((rec = find_uuid(od, RT_USERS, uu)) != NULL) {
		return rec;
	}
	if (parse_compat(uu, &type, &id) && type == MBR_REC_TYPE_USER) {
		return store_find_id(&od->store, RT_USERS, "uid", id);
	}
	return NULL;
}

static const pl_t *
group_by_uuid(struct od *od, const uint8_t *uu)
{
	const pl_t *rec;
	uint32_t id;
	int type;

	if (uu == NULL) {
		return NULL;
	}
	if ((rec = find_uuid(od, RT_GROUPS, uu)) != NULL) {
		return rec;
	}
	if (parse_compat(uu, &type, &id) && type == MBR_REC_TYPE_GROUP) {
		return store_find_id(&od->store, RT_GROUPS, "gid", id);
	}
	return NULL;
}

static pl_t *
list_reply(struct od *od, enum rtype t)
{
	const char *path2 = t == RT_USERS ? od->master_passwd_path : NULL;
	const char *path = t == RT_USERS ? od->passwd_path : od->group_path;
	pl_t *list = pl_array(), *d, *e;
	const pl_t *rec;
	const char *name;
	size_t i;

	for (i = 0; i < store_count(&od->store, t); i++) {
		rec = store_rec(&od->store, t, i);
		name = rec_first(rec, "name");
		if (rec == NULL || name_in_file(path, name) || name_in_file(path2, name)) {
			continue;
		}
		e = t == RT_USERS ? user_entry(rec) : group_entry(rec);
		if (e != NULL) {
			pl_array_append(list, e);
		}
	}
	d = pl_dict();
	pl_dict_set(d, "result", list);
	return with_error(d, 0);
}

static pl_t *
grouplist_reply(struct od *od, const pl_t *req)
{
	const pl_t *user = store_find(&od->store, RT_USERS, pl_str(pl_dict_get(req, "name")));
	const pl_t *n = pl_dict_get(req, "ngroups");
	uint32_t max = 16, *gids;
	pl_t *list, *d;
	size_t i;

	if (pl_is(n, PL_INT) && n->i > 0) {
		max = n->i > 65536 ? 65536 : (uint32_t)n->i;
	}
	if (user == NULL) {
		d = pl_dict();
		pl_dict_set(d, "count", pl_int(0));
		return with_error(d, ENOENT);
	}
	list = od_user_groups(od, user, max);
	gids = calloc(list->count + 1, sizeof(*gids));
	if (gids == NULL) {
		abort();
	}
	for (i = 0; i < list->count; i++) {
		gids[i] = (uint32_t)list->items[i]->i;
	}
	d = pl_dict();
	pl_dict_set(d, "count", pl_int((int64_t)list->count));
	pl_dict_set(d, "groups", pl_data(gids, list->count * sizeof(*gids)));
	free(gids);
	pl_free(list);
	return with_error(d, 0);
}

pl_t *
od_libinfo(struct od *od, const char *proc, const pl_t *req)
{
	uint32_t id;
	pl_t *d;

	store_refresh(&od->store, RT_USERS);
	store_refresh(&od->store, RT_GROUPS);
	if (proc == NULL) {
		return with_error(NULL, EINVAL);
	}
	if (strcmp(proc, "getpwnam") == 0) {
		return item_reply(user_entry(store_find(&od->store, RT_USERS,
		    pl_str(pl_dict_get(req, "name")))));
	}
	if (strcmp(proc, "getpwuid") == 0) {
		return item_reply(req_id(req, "uid", &id) ?
		    user_entry(store_find_id(&od->store, RT_USERS, "uid", id)) : NULL);
	}
	if (strcmp(proc, "getpwuuid") == 0) {
		return item_reply(user_entry(user_by_uuid(od, req_uuid(req, "uuid"))));
	}
	if (strcmp(proc, "getpwent") == 0) {
		return list_reply(od, RT_USERS);
	}
	if (strcmp(proc, "getgrnam") == 0) {
		return item_reply(group_entry(store_find(&od->store, RT_GROUPS,
		    pl_str(pl_dict_get(req, "name")))));
	}
	if (strcmp(proc, "getgrgid") == 0) {
		return item_reply(req_id(req, "gid", &id) ?
		    group_entry(store_find_id(&od->store, RT_GROUPS, "gid", id)) : NULL);
	}
	if (strcmp(proc, "getgruuid") == 0) {
		return item_reply(group_entry(group_by_uuid(od, req_uuid(req, "uuid"))));
	}
	if (strcmp(proc, "getgrent") == 0) {
		return list_reply(od, RT_GROUPS);
	}
	if (strcmp(proc, "getgrouplist") == 0) {
		return grouplist_reply(od, req);
	}
	if (strcmp(proc, "innetgr") == 0) {
		d = pl_dict();
		pl_dict_set(d, "result", pl_bool(false));
		return with_error(d, 0);
	}
	return with_error(NULL, ENOENT);
}

struct principal {
	int rectype;
	const pl_t *rec;
	uint32_t id;
	bool has_id;
};

static int
req_name(const pl_t *v, char *buf, size_t size)
{
	size_t len;

	if (!pl_is(v, PL_DATA) && !pl_is(v, PL_STRING)) {
		return EINVAL;
	}
	len = v->len;
	if (len > 0 && v->bytes[len - 1] == 0) {
		len--;
	}
	if (len == 0 || len >= size || memchr(v->bytes, 0, len) != NULL) {
		return EINVAL;
	}
	memcpy(buf, v->bytes, len);
	buf[len] = '\0';
	return 0;
}

static int
resolve(struct od *od, int64_t type, const pl_t *ident, struct principal *p)
{
	char name[256];
	uint32_t id;
	int rt;

	memset(p, 0, sizeof(*p));
	switch (type) {
	case ID_TYPE_UID:
	case ID_TYPE_GID:
		if (!pl_is(ident, PL_DATA) || ident->len != sizeof(uint32_t)) {
			return EINVAL;
		}
		memcpy(&id, ident->bytes, sizeof(id));
		p->rectype = type == ID_TYPE_UID ? MBR_REC_TYPE_USER : MBR_REC_TYPE_GROUP;
		p->rec = type == ID_TYPE_UID ? store_find_id(&od->store, RT_USERS, "uid", id) :
		    store_find_id(&od->store, RT_GROUPS, "gid", id);
		p->id = id;
		p->has_id = true;
		return 0;
	case ID_TYPE_UUID:
		if (!pl_is(ident, PL_DATA) || ident->len != 16) {
			return EINVAL;
		}
		if ((p->rec = find_uuid(od, RT_USERS, ident->bytes)) != NULL) {
			p->rectype = MBR_REC_TYPE_USER;
			p->has_id = rec_id(p->rec, "uid", &p->id);
			return 0;
		}
		if ((p->rec = find_uuid(od, RT_GROUPS, ident->bytes)) != NULL) {
			p->rectype = MBR_REC_TYPE_GROUP;
			p->has_id = rec_id(p->rec, "gid", &p->id);
			return 0;
		}
		if (!parse_compat(ident->bytes, &rt, &id)) {
			return ENOENT;
		}
		p->rectype = rt;
		p->id = id;
		p->has_id = true;
		p->rec = rt == MBR_REC_TYPE_USER ? store_find_id(&od->store, RT_USERS, "uid", id) :
		    store_find_id(&od->store, RT_GROUPS, "gid", id);
		return 0;
	case ID_TYPE_USERNAME:
	case ID_TYPE_USER_NFS:
	case ID_TYPE_GROUPNAME:
	case ID_TYPE_GROUP_NFS:
	case ID_TYPE_NAME:
		if (req_name(ident, name, sizeof(name)) != 0) {
			return EINVAL;
		}
		if (type != ID_TYPE_GROUPNAME && type != ID_TYPE_GROUP_NFS &&
		    (p->rec = store_find(&od->store, RT_USERS, name)) != NULL) {
			p->rectype = MBR_REC_TYPE_USER;
			p->has_id = rec_id(p->rec, "uid", &p->id);
			return 0;
		}
		if (type != ID_TYPE_USERNAME && type != ID_TYPE_USER_NFS &&
		    (p->rec = store_find(&od->store, RT_GROUPS, name)) != NULL) {
			p->rectype = MBR_REC_TYPE_GROUP;
			p->has_id = rec_id(p->rec, "gid", &p->id);
			return 0;
		}
		return ENOENT;
	default:
		return ENOENT;
	}
}

static pl_t *
translate(struct od *od, const pl_t *req)
{
	const pl_t *type = pl_dict_get(req, "type"), *want = pl_dict_get(req, "requesting");
	struct principal p;
	uint8_t uu[16];
	const char *name;
	pl_t *d;
	int rc;

	if (!pl_is(type, PL_INT) || !pl_is(want, PL_INT)) {
		return with_error(NULL, EINVAL);
	}
	rc = resolve(od, type->i, pl_dict_get(req, "identifier"), &p);
	if (rc != 0) {
		return with_error(NULL, rc);
	}
	d = pl_dict();
	pl_dict_set(d, "rectype", pl_int(p.rectype));
	switch (want->i) {
	case ID_TYPE_UUID:
		if (p.rec != NULL ? !rec_uuid(p.rec, p.rectype, uu) : !p.has_id) {
			break;
		}
		if (p.rec == NULL) {
			compat_uuid(p.rectype, p.id, uu);
		}
		pl_dict_set(d, "identifier", pl_data(uu, 16));
		return with_error(d, 0);
	case ID_TYPE_UID:
	case ID_TYPE_GID:
	case ID_TYPE_UID_OR_GID:
		if (!p.has_id || (want->i == ID_TYPE_UID && p.rectype != MBR_REC_TYPE_USER) ||
		    (want->i == ID_TYPE_GID && p.rectype != MBR_REC_TYPE_GROUP)) {
			break;
		}
		pl_dict_set(d, "identifier", pl_data(&p.id, sizeof(p.id)));
		return with_error(d, 0);
	case ID_TYPE_USERNAME:
	case ID_TYPE_GROUPNAME:
	case ID_TYPE_NAME:
		if (p.rec == NULL || (want->i == ID_TYPE_USERNAME && p.rectype != MBR_REC_TYPE_USER) ||
		    (want->i == ID_TYPE_GROUPNAME && p.rectype != MBR_REC_TYPE_GROUP) ||
		    (name = rec_first(p.rec, "name")) == NULL) {
			break;
		}
		pl_dict_set(d, "identifier", pl_data(name, strlen(name) + 1));
		return with_error(d, 0);
	default:
		break;
	}
	pl_free(d);
	return with_error(NULL, ENOENT);
}

static pl_t *
member_reply(int64_t error, bool ismember)
{
	pl_t *d = pl_dict();

	pl_dict_set(d, "ismember", pl_bool(ismember));
	return with_error(d, error);
}

static pl_t *
check_membership(struct od *od, const pl_t *req)
{
	const pl_t *ut = pl_dict_get(req, "user_idtype"), *gt = pl_dict_get(req, "group_idtype");
	struct principal u, g;
	uint32_t ugid;
	int rc;

	if (!pl_is(ut, PL_INT) || !pl_is(gt, PL_INT)) {
		return member_reply(EINVAL, false);
	}
	if (ut->i != ID_TYPE_UID && ut->i != ID_TYPE_UUID && ut->i != ID_TYPE_USERNAME) {
		return member_reply(EINVAL, false);
	}
	rc = resolve(od, ut->i, pl_dict_get(req, "user_id"), &u);
	if (rc != 0 || u.rectype != MBR_REC_TYPE_USER || u.rec == NULL) {
		return member_reply(rc == EINVAL ? EINVAL : ENOENT, false);
	}
	if (gt->i != ID_TYPE_GID && gt->i != ID_TYPE_UUID && gt->i != ID_TYPE_GROUPNAME &&
	    gt->i != ID_TYPE_GROUP_NFS && gt->i != ID_TYPE_SID) {
		return member_reply(EINVAL, false);
	}
	rc = resolve(od, gt->i, pl_dict_get(req, "group_id"), &g);
	if (rc == EINVAL) {
		return member_reply(EINVAL, false);
	}
	if (rc != 0 || g.rectype != MBR_REC_TYPE_GROUP) {
		return member_reply(0, false);
	}
	if (g.rec == NULL) {
		return member_reply(0, g.has_id && (g.id == OD_EVERYONE_GID ||
		    (rec_id(u.rec, "gid", &ugid) && ugid == g.id)));
	}
	return member_reply(0, od_is_member(od, u.rec, g.rec));
}

static pl_t *
check_service(struct od *od, const pl_t *req)
{
	const char *service = pl_str(pl_dict_get(req, "service"));
	const pl_t *group;
	struct principal u;
	char name[300];
	int rc;

	if (service == NULL || strlen(service) > 200) {
		return member_reply(EINVAL, false);
	}
	rc = resolve(od, ID_TYPE_UUID, pl_dict_get(req, "user_id"), &u);
	if (rc != 0 || u.rectype != MBR_REC_TYPE_USER || u.rec == NULL) {
		return member_reply(rc == EINVAL ? EINVAL : ENOENT, false);
	}
	snprintf(name, sizeof(name), "com.apple.access_%s", service);
	group = store_find(&od->store, RT_GROUPS, name);
	if (group == NULL) {
		return member_reply(ENOENT, false);
	}
	return member_reply(0, od_is_member(od, u.rec, group));
}

pl_t *
od_membership(struct od *od, const char *proc, const pl_t *req)
{
	store_refresh(&od->store, RT_USERS);
	store_refresh(&od->store, RT_GROUPS);
	if (proc == NULL) {
		return with_error(NULL, EINVAL);
	}
	if (strcmp(proc, "mbr_identifier_translate") == 0) {
		return translate(od, req);
	}
	if (strcmp(proc, "mbr_check_membership") == 0) {
		return check_membership(od, req);
	}
	if (strcmp(proc, "mbr_check_service_membership") == 0) {
		return check_service(od, req);
	}
	if (strcmp(proc, "mbr_set_identifier_ttl") == 0 || strcmp(proc, "mbr_cache_flush") == 0) {
		return with_error(NULL, 0);
	}
	return with_error(NULL, ENOTSUP);
}
