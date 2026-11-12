/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 The Blueberry Pie OS Authors
 */
#include <sys/stat.h>

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "od.h"

#define MAX_RECORD_FILE (1024 * 1024)

#ifdef __MACH__
#define ST_MTIM st_mtimespec
#else
#define ST_MTIM st_mtim
#endif

const char *
rec_first(const pl_t *rec, const char *key)
{
	return pl_str(pl_array_get(pl_dict_get(rec, key), 0));
}

bool
rec_has(const pl_t *rec, const char *key, const char *value)
{
	const pl_t *a = pl_dict_get(rec, key);
	const char *s;
	size_t i;

	for (i = 0; a != NULL && i < a->count; i++) {
		if ((s = pl_str(a->items[i])) != NULL && strcmp(s, value) == 0) {
			return true;
		}
	}
	return false;
}

bool
rec_name_matches(const pl_t *rec, const char *name)
{
	return rec_has(rec, "name", name);
}

bool
rec_id(const pl_t *rec, const char *key, uint32_t *id)
{
	return parse_id(rec_first(rec, key), id);
}

bool
rec_valid(const pl_t *rec)
{
	size_t i, j;
	const pl_t *a;

	if (!pl_is(rec, PL_DICT)) {
		return false;
	}
	for (i = 0; i < rec->count; i++) {
		a = rec->items[i];
		if (!pl_is(a, PL_ARRAY)) {
			return false;
		}
		for (j = 0; j < a->count; j++) {
			if (!pl_is(a->items[j], PL_STRING) && !pl_is(a->items[j], PL_DATA)) {
				return false;
			}
		}
	}
	return store_valid_name(rec_first(rec, "name"));
}

bool
store_valid_name(const char *name)
{
	size_t n;

	if (name == NULL || (n = strlen(name)) == 0 || n > OD_MAX_NAME || name[0] == '.' || name[0] == '-') {
		return false;
	}
	for (; *name != '\0'; name++) {
		if (*name == '/' || (unsigned char)*name < 0x20 || *name == 0x7F || *name == ':') {
			return false;
		}
	}
	return true;
}

static int
mkdirs(const char *path)
{
	char *p = strdup(path), *s;
	int rc = 0;

	if (p == NULL) {
		return -1;
	}
	for (s = p + 1; rc == 0; s++) {
		if (*s == '/' || *s == '\0') {
			char c = *s;

			*s = '\0';
			if (mkdir(p, 0700) != 0 && errno != EEXIST) {
				rc = -1;
			}
			*s = c;
			if (c == '\0') {
				break;
			}
		}
	}
	free(p);
	return rc;
}

static void
remove_temporaries(const char *path)
{
	struct dirent *de;
	struct stat st;
	DIR *dir = opendir(path);

	while (dir != NULL && (de = readdir(dir)) != NULL) {
		if (de->d_name[0] == '.' && strcmp(de->d_name, ".") != 0 && strcmp(de->d_name, "..") != 0 &&
		    fstatat(dirfd(dir), de->d_name, &st, AT_SYMLINK_NOFOLLOW) == 0 && S_ISREG(st.st_mode)) {
			unlinkat(dirfd(dir), de->d_name, 0);
		}
	}
	if (dir != NULL) {
		closedir(dir);
	}
}

int
store_init(struct store *s, const char *root)
{
	char path[1024];
	int t;

	memset(s, 0, sizeof(*s));
	s->root = strdup(root);
	if (s->root == NULL) {
		return -1;
	}
	for (t = 0; t < RT_COUNT; t++) {
		snprintf(path, sizeof(path), "%s/%s", root, rtype_dir((enum rtype)t));
		if (mkdirs(path) != 0) {
			return -1;
		}
		remove_temporaries(path);
	}
	return 0;
}

static void
index_free(struct index *x)
{
	free(x->s);
	x->s = NULL;
	x->size = 0;
}

void
store_free(struct store *s)
{
	struct rdir *d;
	size_t i;
	int t;

	for (t = 0; t < RT_COUNT; t++) {
		d = &s->dirs[t];
		for (i = 0; i < d->count; i++) {
			pl_free(d->e[i].rec);
			free(d->e[i].file);
		}
		free(d->e);
		d->e = NULL;
		d->count = d->cap = 0;
		index_free(&d->files);
		index_free(&d->names);
		index_free(&d->ids);
		d->settled = false;
	}
	free(s->root);
	s->root = NULL;
}

static pl_t *
load_file(int dirfd, const char *file, struct stat *st, bool *ioerr)
{
	uint8_t *buf;
	ssize_t n = 0;
	size_t got = 0;
	pl_t *rec;
	int fd;

	*ioerr = false;
	fd = openat(dirfd, file, O_RDONLY | O_NOFOLLOW);
	if (fd < 0) {
		*ioerr = errno != ENOENT && errno != ELOOP;
		return NULL;
	}
	if (fstat(fd, st) != 0) {
		*ioerr = true;
		close(fd);
		return NULL;
	}
	if (!S_ISREG(st->st_mode) || st->st_size > MAX_RECORD_FILE) {
		close(fd);
		return NULL;
	}
	buf = malloc((size_t)st->st_size + 1);
	if (buf == NULL) {
		*ioerr = true;
		close(fd);
		return NULL;
	}
	while (got < (size_t)st->st_size && (n = read(fd, buf + got, (size_t)st->st_size - got)) > 0) {
		got += (size_t)n;
	}
	close(fd);
	if (n < 0) {
		*ioerr = true;
		free(buf);
		return NULL;
	}
	rec = pl_bplist_read(buf, got);
	od_wipe(buf, got);
	free(buf);
	if (rec != NULL && !rec_valid(rec)) {
		pl_free(rec);
		rec = NULL;
	}
	return rec;
}

static int
entry_cmp(const void *a, const void *b)
{
	return strcmp(((const struct entry *)a)->file, ((const struct entry *)b)->file);
}

static const char *
id_key(enum rtype t)
{
	return t == RT_USERS ? "uid" : "gid";
}

static uint64_t
hash_str(const char *p)
{
	uint64_t h = 14695981039346656037ULL;

	for (; *p != '\0'; p++) {
		h = (h ^ (unsigned char)*p) * 1099511628211ULL;
	}
	return h;
}

static uint64_t
hash_id(uint32_t id)
{
	uint64_t h = (uint64_t)id * 0x9E3779B97F4A7C15ULL;

	return h ^ (h >> 29);
}

static void
index_reset(struct index *x, size_t n)
{
	size_t size = 16, i;

	while (size < n * 2) {
		size *= 2;
	}
	free(x->s);
	x->s = malloc(size * sizeof(*x->s));
	if (x->s == NULL) {
		abort();
	}
	for (i = 0; i < size; i++) {
		x->s[i].key = NULL;
		x->s[i].id = 0;
		x->s[i].idx = SIZE_MAX;
	}
	x->size = size;
}

static struct slot *
index_slot(const struct index *x, const char *key, uint32_t id)
{
	size_t i;

	if (x->size == 0) {
		return NULL;
	}
	i = (size_t)(key != NULL ? hash_str(key) : hash_id(id)) & (x->size - 1);
	while (x->s[i].idx != SIZE_MAX) {
		if (key != NULL ? strcmp(x->s[i].key, key) == 0 : x->s[i].id == id) {
			break;
		}
		i = (i + 1) & (x->size - 1);
	}
	return &x->s[i];
}

static size_t
index_get(const struct index *x, const char *key, uint32_t id)
{
	const struct slot *sl = index_slot(x, key, id);

	return sl != NULL ? sl->idx : SIZE_MAX;
}

static void
index_put(struct index *x, const char *key, uint32_t id, size_t idx)
{
	struct slot *sl = index_slot(x, key, id);

	if (sl->idx == SIZE_MAX) {
		sl->key = key;
		sl->id = id;
		sl->idx = idx;
	}
}

static void
index_files(struct rdir *d, size_t n)
{
	size_t i;

	index_reset(&d->files, n);
	for (i = 0; i < d->count; i++) {
		index_put(&d->files, d->e[i].file, 0, i);
	}
}

static void
index_build(struct rdir *d, enum rtype t)
{
	const pl_t *a;
	const char *name;
	size_t i, j, n = 0;
	uint32_t id;

	index_files(d, d->count);
	for (i = 0; i < d->count; i++) {
		a = d->e[i].rec != NULL ? pl_dict_get(d->e[i].rec, "name") : NULL;
		n += a != NULL ? a->count : 0;
	}
	index_reset(&d->names, n);
	index_reset(&d->ids, d->count);
	for (i = 0; i < d->count; i++) {
		if (d->e[i].rec == NULL) {
			continue;
		}
		a = pl_dict_get(d->e[i].rec, "name");
		for (j = 0; a != NULL && j < a->count; j++) {
			if ((name = pl_str(a->items[j])) != NULL) {
				index_put(&d->names, name, 0, i);
			}
		}
		if (rec_id(d->e[i].rec, id_key(t), &id)) {
			index_put(&d->ids, NULL, id, i);
		}
	}
}

static struct entry *
find_entry(struct rdir *d, const char *file)
{
	size_t i = index_get(&d->files, file, 0);

	return i != SIZE_MAX ? &d->e[i] : NULL;
}

#ifdef CLOCK_UPTIME_RAW
#define STEADY_CLOCK CLOCK_UPTIME_RAW
#else
#define STEADY_CLOCK CLOCK_MONOTONIC
#endif

static int64_t
clock_offset(struct timespec *wall)
{
	struct timespec steady;

	clock_gettime(CLOCK_REALTIME, wall);
	clock_gettime(STEADY_CLOCK, &steady);
	return ((int64_t)wall->tv_sec - steady.tv_sec) * 1000000000 + (wall->tv_nsec - steady.tv_nsec);
}

static bool
unchanged(const struct store *s, enum rtype t, unsigned shared)
{
	struct timespec wall;
	int64_t step;
	const struct rdir *d = &s->dirs[t];
	char path[1024];
	struct stat st;

	if (!d->settled || d->gen != s->gen || d->shared_gen != shared) {
		return false;
	}
	step = clock_offset(&wall) - d->offset;
	if (step > 1000000000 || step < -1000000000) {
		return false;
	}
	snprintf(path, sizeof(path), "%s/%s", s->root, rtype_dir(t));
	return stat(path, &st) == 0 && st.st_dev == d->dev && st.st_ino == d->ino &&
	    st.ST_MTIM.tv_sec == d->mtime.tv_sec && st.ST_MTIM.tv_nsec == d->mtime.tv_nsec;
}

void
store_refresh(struct store *s, enum rtype t)
{
	struct rdir *d = &s->dirs[t];
	unsigned shared = s->shared_gen != NULL ? atomic_load(s->shared_gen) : 0;
	char path[1024];
	struct dirent *de;
	struct entry *e;
	struct timespec now;
	struct stat st;
	size_t i, j, n;
	bool failed, ioerr;
	pl_t *rec;
	DIR *dir;

	if (unchanged(s, t, shared)) {
		return;
	}
	snprintf(path, sizeof(path), "%s/%s", s->root, rtype_dir(t));
	d->offset = clock_offset(&now);
	dir = opendir(path);
	failed = dir == NULL && errno != ENOENT;
	d->settled = dir != NULL && fstat(dirfd(dir), &st) == 0 && st.ST_MTIM.tv_sec < now.tv_sec - 1;
	if (d->settled) {
		d->dev = st.st_dev;
		d->ino = st.st_ino;
		d->mtime = st.ST_MTIM;
	}
	d->gen = s->gen;
	d->shared_gen = shared;
	for (i = 0; i < d->count; i++) {
		d->e[i].seen = false;
	}
	while (dir != NULL) {
		errno = 0;
		de = readdir(dir);
		if (de == NULL) {
			if (errno != 0) {
				failed = true;
			}
			break;
		}
		n = strlen(de->d_name);
		if (de->d_name[0] == '.' || n <= 6 || strcmp(de->d_name + n - 6, ".plist") != 0) {
			continue;
		}
		e = find_entry(d, de->d_name);
		if (fstatat(dirfd(dir), de->d_name, &st, AT_SYMLINK_NOFOLLOW) != 0) {
			if (errno != ENOENT) {
				d->settled = false;
				if (e != NULL) {
					e->seen = true;
				}
			}
			continue;
		}
		if (!S_ISREG(st.st_mode)) {
			continue;
		}
		if (e != NULL && e->dev == st.st_dev && e->ino == st.st_ino && e->size == st.st_size &&
		    e->mtime.tv_sec == st.ST_MTIM.tv_sec && e->mtime.tv_nsec == st.ST_MTIM.tv_nsec) {
			e->seen = true;
			continue;
		}
		rec = load_file(dirfd(dir), de->d_name, &st, &ioerr);
		if (ioerr) {
			d->settled = false;
			if (e != NULL) {
				e->seen = true;
			}
			continue;
		}
		if (e == NULL) {
			if (d->count == d->cap) {
				d->cap = d->cap ? d->cap * 2 : 32;
				d->e = realloc(d->e, d->cap * sizeof(*d->e));
				if (d->e == NULL) {
					abort();
				}
			}
			if ((d->count + 1) * 2 > d->files.size) {
				index_files(d, d->cap);
			}
			e = &d->e[d->count++];
			memset(e, 0, sizeof(*e));
			e->file = strdup(de->d_name);
			if (e->file == NULL) {
				abort();
			}
			index_put(&d->files, e->file, 0, d->count - 1);
		}
		pl_free(e->rec);
		e->rec = rec;
		e->dev = st.st_dev;
		e->ino = st.st_ino;
		e->size = st.st_size;
		e->mtime = st.ST_MTIM;
		e->seen = true;
	}
	if (dir != NULL) {
		closedir(dir);
	}
	if (failed) {
		d->settled = false;
	}
	for (i = 0, j = 0; i < d->count; i++) {
		if (d->e[i].seen || failed) {
			d->e[j++] = d->e[i];
		} else {
			pl_free(d->e[i].rec);
			free(d->e[i].file);
		}
	}
	d->count = j;
	if (d->count > 1) {
		qsort(d->e, d->count, sizeof(*d->e), entry_cmp);
	}
	index_build(d, t);
}

size_t
store_count(const struct store *s, enum rtype t)
{
	return s->dirs[t].count;
}

pl_t *
store_rec(const struct store *s, enum rtype t, size_t i)
{
	return i < s->dirs[t].count ? s->dirs[t].e[i].rec : NULL;
}

pl_t *
store_find(struct store *s, enum rtype t, const char *name)
{
	size_t i;

	if (name == NULL) {
		return NULL;
	}
	i = index_get(&s->dirs[t].names, name, 0);
	return i != SIZE_MAX ? s->dirs[t].e[i].rec : NULL;
}

bool
store_file_name(const struct store *s, enum rtype t, const pl_t *rec, char *buf, size_t size)
{
	const struct rdir *d = &s->dirs[t];
	size_t i, n;

	for (i = 0; i < d->count; i++) {
		if (d->e[i].rec == rec) {
			n = strlen(d->e[i].file) - 6;
			if (n >= size) {
				return false;
			}
			memcpy(buf, d->e[i].file, n);
			buf[n] = '\0';
			return true;
		}
	}
	return false;
}

pl_t *
store_find_value(struct store *s, enum rtype t, const char *key, const char *value)
{
	size_t i;
	pl_t *rec;

	for (i = 0; i < store_count(s, t); i++) {
		rec = store_rec(s, t, i);
		if (rec != NULL && rec_has(rec, key, value)) {
			return rec;
		}
	}
	return NULL;
}

pl_t *
store_find_id(struct store *s, enum rtype t, const char *key, uint32_t id)
{
	size_t i;
	uint32_t v;
	pl_t *rec;

	if (strcmp(key, id_key(t)) == 0) {
		i = index_get(&s->dirs[t].ids, NULL, id);
		return i != SIZE_MAX ? s->dirs[t].e[i].rec : NULL;
	}
	for (i = 0; i < store_count(s, t); i++) {
		rec = store_rec(s, t, i);
		if (rec != NULL && rec_id(rec, key, &v) && v == id) {
			return rec;
		}
	}
	return NULL;
}

static int
write_all(int fd, const uint8_t *p, size_t len)
{
	ssize_t n;

	while (len > 0) {
		n = write(fd, p, len);
		if (n < 0) {
			if (errno == EINTR) {
				continue;
			}
			return -1;
		}
		p += n;
		len -= (size_t)n;
	}
	return 0;
}

static int
sync_dir(const char *path)
{
	int fd = open(path, O_RDONLY | O_DIRECTORY);
	int rc;

	if (fd < 0) {
		return -1;
	}
	rc = fsync(fd);
	close(fd);
	return rc;
}

int
store_write(struct store *s, enum rtype t, const pl_t *rec, const char *oldname)
{
	char dir[1024], tmp[1100], final[1100], old[1100];
	const char *name = rec_first(rec, "name");
	uint8_t *data;
	size_t len;
	int fd, rc;

	if (!rec_valid(rec) || (oldname != NULL && !store_valid_name(oldname))) {
		errno = EINVAL;
		return -1;
	}
	if (pl_bplist_write(rec, &data, &len) != 0) {
		errno = EINVAL;
		return -1;
	}
	if (len > MAX_RECORD_FILE) {
		od_wipe(data, len);
		free(data);
		errno = EFBIG;
		return -1;
	}
	snprintf(dir, sizeof(dir), "%s/%s", s->root, rtype_dir(t));
	snprintf(tmp, sizeof(tmp), "%s/.%s.XXXXXX", dir, name);
	snprintf(final, sizeof(final), "%s/%s.plist", dir, name);
	fd = mkstemp(tmp);
	if (fd < 0) {
		od_wipe(data, len);
		free(data);
		return -1;
	}
	rc = fchmod(fd, 0600);
	if (rc == 0) {
		rc = write_all(fd, data, len);
	}
	if (rc == 0) {
		rc = fsync(fd);
	}
	od_wipe(data, len);
	free(data);
	if (close(fd) != 0) {
		rc = -1;
	}
	if (rc == 0) {
		rc = rename(tmp, final);
	}
	if (rc != 0) {
		int e = errno;

		unlink(tmp);
		errno = e;
		return -1;
	}
	if (oldname != NULL && strcmp(oldname, name) != 0) {
		snprintf(old, sizeof(old), "%s/%s.plist", dir, oldname);
		unlink(old);
	}
	sync_dir(dir);
	s->gen++;
	store_refresh(s, t);
	return 0;
}

int
store_delete(struct store *s, enum rtype t, const char *name)
{
	char dir[1024], path[1100];

	if (!store_valid_name(name)) {
		errno = EINVAL;
		return -1;
	}
	snprintf(dir, sizeof(dir), "%s/%s", s->root, rtype_dir(t));
	snprintf(path, sizeof(path), "%s/%s.plist", dir, name);
	if (unlink(path) != 0) {
		return -1;
	}
	sync_dir(dir);
	s->gen++;
	store_refresh(s, t);
	return 0;
}
