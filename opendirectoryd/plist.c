/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 The Blueberry Pie OS Authors
 */
#include <sys/types.h>

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "plist.h"

#define PL_MAX_DEPTH 64
#define PL_MAX_NODES 200000
#define PL_EXPANSION 32
#define PL_SLACK (64 * 1024)

void
od_wipe(void *p, size_t len)
{
	volatile uint8_t *v = p;

	while (len-- > 0) {
		*v++ = 0;
	}
}

static pl_t *
pl_new(enum pl_type t)
{
	pl_t *p = calloc(1, sizeof(*p));

	if (p == NULL) {
		abort();
	}
	p->type = t;
	return p;
}

static void *
xmalloc(size_t n)
{
	void *p = malloc(n ? n : 1);

	if (p == NULL) {
		abort();
	}
	return p;
}

pl_t *
pl_dict(void)
{
	return pl_new(PL_DICT);
}

pl_t *
pl_array(void)
{
	return pl_new(PL_ARRAY);
}

pl_t *
pl_string_n(const char *s, size_t len)
{
	pl_t *p = pl_new(PL_STRING);

	p->bytes = xmalloc(len + 1);
	memcpy(p->bytes, s, len);
	p->bytes[len] = 0;
	p->len = len;
	return p;
}

pl_t *
pl_string(const char *s)
{
	return pl_string_n(s, strlen(s));
}

pl_t *
pl_data(const void *d, size_t len)
{
	pl_t *p = pl_new(PL_DATA);

	p->bytes = xmalloc(len);
	if (len > 0) {
		memcpy(p->bytes, d, len);
	}
	p->len = len;
	return p;
}

pl_t *
pl_int(int64_t v)
{
	pl_t *p = pl_new(PL_INT);

	p->i = v;
	return p;
}

pl_t *
pl_bool(bool v)
{
	pl_t *p = pl_new(PL_BOOL);

	p->i = v ? 1 : 0;
	return p;
}

static void
grow(pl_t *p)
{
	if (p->count < p->cap) {
		return;
	}
	p->cap = p->cap ? p->cap * 2 : 8;
	p->items = realloc(p->items, p->cap * sizeof(*p->items));
	if (p->items == NULL) {
		abort();
	}
	if (p->type == PL_DICT) {
		p->keys = realloc(p->keys, p->cap * sizeof(*p->keys));
		if (p->keys == NULL) {
			abort();
		}
	}
}

static void
dict_append(pl_t *d, char *key, pl_t *v)
{
	grow(d);
	d->keys[d->count] = key;
	d->items[d->count] = v;
	d->count++;
}

static char *
xstrdup(const char *s)
{
	size_t n = strlen(s) + 1;
	char *c = xmalloc(n);

	memcpy(c, s, n);
	return c;
}

static int
key_cmp(const void *a, const void *b)
{
	return strcmp(*(char *const *)a, *(char *const *)b);
}

static bool
has_duplicate_keys(const pl_t *d)
{
	char **k;
	size_t i;
	bool dup = false;

	if (d->count < 2) {
		return false;
	}
	k = xmalloc(d->count * sizeof(*k));
	memcpy(k, d->keys, d->count * sizeof(*k));
	qsort(k, d->count, sizeof(*k), key_cmp);
	for (i = 1; i < d->count && !dup; i++) {
		dup = strcmp(k[i - 1], k[i]) == 0;
	}
	free(k);
	return dup;
}

void
pl_free(pl_t *p)
{
	size_t i;

	if (p == NULL) {
		return;
	}
	for (i = 0; i < p->count; i++) {
		pl_free(p->items[i]);
		if (p->keys != NULL) {
			od_wipe(p->keys[i], strlen(p->keys[i]));
			free(p->keys[i]);
		}
	}
	free(p->items);
	free(p->keys);
	if (p->bytes != NULL) {
		od_wipe(p->bytes, p->len);
		free(p->bytes);
	}
	free(p);
}

pl_t *
pl_copy(const pl_t *p)
{
	pl_t *c;
	size_t i;

	if (p == NULL) {
		return NULL;
	}
	switch (p->type) {
	case PL_STRING:
		return pl_string_n((const char *)p->bytes, p->len);
	case PL_DATA:
		return pl_data(p->bytes, p->len);
	case PL_INT:
		return pl_int(p->i);
	case PL_BOOL:
		return pl_bool(p->i != 0);
	case PL_REAL:
		c = pl_new(PL_REAL);
		c->r = p->r;
		return c;
	case PL_ARRAY:
		c = pl_array();
		for (i = 0; i < p->count; i++) {
			pl_array_append(c, pl_copy(p->items[i]));
		}
		return c;
	case PL_DICT:
		c = pl_dict();
		for (i = 0; i < p->count; i++) {
			dict_append(c, xstrdup(p->keys[i]), pl_copy(p->items[i]));
		}
		return c;
	}
	return NULL;
}

bool
pl_equal(const pl_t *a, const pl_t *b)
{
	size_t i;

	if (a == NULL || b == NULL) {
		return a == b;
	}
	if (a->type != b->type) {
		return false;
	}
	switch (a->type) {
	case PL_STRING:
	case PL_DATA:
		return a->len == b->len && (a->len == 0 || memcmp(a->bytes, b->bytes, a->len) == 0);
	case PL_INT:
	case PL_BOOL:
		return a->i == b->i;
	case PL_REAL:
		return a->r == b->r;
	case PL_ARRAY:
		if (a->count != b->count) {
			return false;
		}
		for (i = 0; i < a->count; i++) {
			if (!pl_equal(a->items[i], b->items[i])) {
				return false;
			}
		}
		return true;
	case PL_DICT:
		if (a->count != b->count) {
			return false;
		}
		for (i = 0; i < a->count; i++) {
			if (!pl_equal(a->items[i], pl_dict_get(b, a->keys[i]))) {
				return false;
			}
		}
		return true;
	}
	return false;
}

static ssize_t
dict_index(const pl_t *d, const char *key)
{
	size_t i;

	if (d == NULL || d->type != PL_DICT) {
		return -1;
	}
	for (i = 0; i < d->count; i++) {
		if (strcmp(d->keys[i], key) == 0) {
			return (ssize_t)i;
		}
	}
	return -1;
}

void
pl_dict_set(pl_t *d, const char *key, pl_t *v)
{
	ssize_t i = dict_index(d, key);
	size_t n;

	if (i >= 0) {
		pl_free(d->items[i]);
		d->items[i] = v;
		return;
	}
	grow(d);
	n = strlen(key);
	d->keys[d->count] = xmalloc(n + 1);
	memcpy(d->keys[d->count], key, n + 1);
	d->items[d->count] = v;
	d->count++;
}

pl_t *
pl_dict_get(const pl_t *d, const char *key)
{
	ssize_t i = dict_index(d, key);

	return i >= 0 ? d->items[i] : NULL;
}

pl_t *
pl_dict_take(pl_t *d, const char *key)
{
	ssize_t i = dict_index(d, key);
	pl_t *v;

	if (i < 0) {
		return NULL;
	}
	v = d->items[i];
	free(d->keys[i]);
	memmove(&d->keys[i], &d->keys[i + 1], (d->count - (size_t)i - 1) * sizeof(*d->keys));
	memmove(&d->items[i], &d->items[i + 1], (d->count - (size_t)i - 1) * sizeof(*d->items));
	d->count--;
	return v;
}

bool
pl_dict_remove(pl_t *d, const char *key)
{
	pl_t *v = pl_dict_take(d, key);

	if (v == NULL) {
		return false;
	}
	pl_free(v);
	return true;
}

void
pl_array_append(pl_t *a, pl_t *v)
{
	grow(a);
	a->items[a->count++] = v;
}

pl_t *
pl_array_get(const pl_t *a, size_t i)
{
	if (a == NULL || a->type != PL_ARRAY || i >= a->count) {
		return NULL;
	}
	return a->items[i];
}

void
pl_array_remove(pl_t *a, size_t i)
{
	if (a == NULL || a->type != PL_ARRAY || i >= a->count) {
		return;
	}
	pl_free(a->items[i]);
	memmove(&a->items[i], &a->items[i + 1], (a->count - i - 1) * sizeof(*a->items));
	a->count--;
}

const char *
pl_str(const pl_t *p)
{
	return (p != NULL && p->type == PL_STRING) ? (const char *)p->bytes : NULL;
}

bool
pl_is(const pl_t *p, enum pl_type t)
{
	return p != NULL && p->type == t;
}

struct buf {
	uint8_t *p;
	size_t len;
	size_t cap;
};

static void
buf_put(struct buf *b, const void *d, size_t n)
{
	if (b->len + n > b->cap) {
		while (b->len + n > b->cap) {
			b->cap = b->cap ? b->cap * 2 : 256;
		}
		b->p = realloc(b->p, b->cap);
		if (b->p == NULL) {
			abort();
		}
	}
	memcpy(b->p + b->len, d, n);
	b->len += n;
}

static void
buf_byte(struct buf *b, uint8_t c)
{
	buf_put(b, &c, 1);
}

static void
buf_be(struct buf *b, uint64_t v, unsigned n)
{
	uint8_t t[8];
	unsigned i;

	for (i = 0; i < n; i++) {
		t[i] = (uint8_t)(v >> (8 * (n - 1 - i)));
	}
	buf_put(b, t, n);
}

static void
put_int_object(struct buf *b, int64_t v)
{
	if (v < 0 || v > 0xFFFFFFFFLL) {
		buf_byte(b, 0x13);
		buf_be(b, (uint64_t)v, 8);
	} else if (v > 0xFFFF) {
		buf_byte(b, 0x12);
		buf_be(b, (uint64_t)v, 4);
	} else if (v > 0xFF) {
		buf_byte(b, 0x11);
		buf_be(b, (uint64_t)v, 2);
	} else {
		buf_byte(b, 0x10);
		buf_be(b, (uint64_t)v, 1);
	}
}

static void
put_header(struct buf *b, uint8_t marker, size_t n)
{
	if (n < 15) {
		buf_byte(b, (uint8_t)(marker | n));
	} else {
		buf_byte(b, (uint8_t)(marker | 0x0F));
		put_int_object(b, (int64_t)n);
	}
}

static size_t
count_objects(const pl_t *p)
{
	size_t n = 1, i;

	if (p->type == PL_DICT) {
		n += p->count;
	}
	if (p->type == PL_DICT || p->type == PL_ARRAY) {
		for (i = 0; i < p->count; i++) {
			n += count_objects(p->items[i]);
		}
	}
	return n;
}

static int
utf8_next(const uint8_t *s, size_t len, size_t *pos, uint32_t *cp)
{
	uint32_t c = s[*pos], min;
	size_t n, i;

	if (c < 0x80) {
		*cp = c;
		(*pos)++;
		return 0;
	} else if ((c & 0xE0) == 0xC0) {
		n = 1;
		c &= 0x1F;
		min = 0x80;
	} else if ((c & 0xF0) == 0xE0) {
		n = 2;
		c &= 0x0F;
		min = 0x800;
	} else if ((c & 0xF8) == 0xF0) {
		n = 3;
		c &= 0x07;
		min = 0x10000;
	} else {
		return -1;
	}
	for (i = 1; i <= n; i++) {
		if (*pos + i >= len || (s[*pos + i] & 0xC0) != 0x80) {
			return -1;
		}
		c = (c << 6) | (s[*pos + i] & 0x3F);
	}
	if (c < min || c > 0x10FFFF || (c >= 0xD800 && c <= 0xDFFF)) {
		return -1;
	}
	*pos += n + 1;
	*cp = c;
	return 0;
}

static int
put_string(struct buf *b, const pl_t *p)
{
	size_t i, pos, units = 0;
	uint32_t cp;
	bool ascii = true;

	for (i = 0; i < p->len; i++) {
		if (p->bytes[i] >= 0x80) {
			ascii = false;
			break;
		}
	}
	if (ascii) {
		put_header(b, 0x50, p->len);
		buf_put(b, p->bytes, p->len);
		return 0;
	}
	for (pos = 0; pos < p->len;) {
		if (utf8_next(p->bytes, p->len, &pos, &cp) != 0) {
			return -1;
		}
		units += cp >= 0x10000 ? 2 : 1;
	}
	put_header(b, 0x60, units);
	for (pos = 0; pos < p->len;) {
		(void)utf8_next(p->bytes, p->len, &pos, &cp);
		if (cp >= 0x10000) {
			cp -= 0x10000;
			buf_be(b, 0xD800 | (cp >> 10), 2);
			buf_be(b, 0xDC00 | (cp & 0x3FF), 2);
		} else {
			buf_be(b, cp, 2);
		}
	}
	return 0;
}

static uint64_t
get_be_host(const uint8_t *t)
{
	uint64_t u;

	memcpy(&u, t, 8);
	return u;
}

struct writer {
	struct buf b;
	uint64_t *offsets;
	size_t next;
	unsigned refsize;
};

static int
write_object(struct writer *w, const pl_t *p, uint64_t *ref)
{
	uint64_t *refs = NULL, r;
	size_t n = 0, i;
	int rc = 0;
	uint8_t t[8];

	*ref = w->next++;
	if (p->type == PL_DICT || p->type == PL_ARRAY) {
		n = p->type == PL_DICT ? 2 * p->count : p->count;
		refs = xmalloc(n * sizeof(*refs));
		for (i = 0; i < p->count && rc == 0; i++) {
			if (p->type == PL_DICT) {
				pl_t key = { .type = PL_STRING, .bytes = (uint8_t *)p->keys[i],
					.len = strlen(p->keys[i]) };
				r = w->next++;
				w->offsets[r] = w->b.len;
				rc = put_string(&w->b, &key);
				refs[i] = r;
				if (rc == 0) {
					rc = write_object(w, p->items[i], &refs[p->count + i]);
				}
			} else {
				rc = write_object(w, p->items[i], &refs[i]);
			}
		}
	}
	if (rc != 0) {
		free(refs);
		return rc;
	}
	w->offsets[*ref] = w->b.len;
	switch (p->type) {
	case PL_STRING:
		rc = put_string(&w->b, p);
		break;
	case PL_DATA:
		put_header(&w->b, 0x40, p->len);
		buf_put(&w->b, p->bytes, p->len);
		break;
	case PL_INT:
		put_int_object(&w->b, p->i);
		break;
	case PL_BOOL:
		buf_byte(&w->b, p->i ? 0x09 : 0x08);
		break;
	case PL_REAL:
		buf_byte(&w->b, 0x23);
		memcpy(t, &p->r, 8);
		buf_be(&w->b, get_be_host(t), 8);
		break;
	case PL_ARRAY:
	case PL_DICT:
		put_header(&w->b, p->type == PL_DICT ? 0xD0 : 0xA0, p->count);
		for (i = 0; i < n; i++) {
			buf_be(&w->b, refs[i], w->refsize);
		}
		break;
	}
	free(refs);
	return rc;
}

int
pl_bplist_write(const pl_t *p, uint8_t **out, size_t *len)
{
	struct writer w = { { NULL, 0, 0 }, NULL, 0, 1 };
	size_t n = count_objects(p), i;
	uint64_t top, table, maxoff;
	unsigned offsize;

	w.refsize = n < 0x100 ? 1 : n < 0x10000 ? 2 : 4;
	w.offsets = xmalloc(n * sizeof(*w.offsets));
	buf_put(&w.b, "bplist00", 8);
	if (write_object(&w, p, &top) != 0) {
		free(w.offsets);
		free(w.b.p);
		return -1;
	}
	table = w.b.len;
	maxoff = table;
	offsize = maxoff < 0x100 ? 1 : maxoff < 0x10000 ? 2 : maxoff < 0x100000000ULL ? 4 : 8;
	for (i = 0; i < n; i++) {
		buf_be(&w.b, w.offsets[i], offsize);
	}
	for (i = 0; i < 6; i++) {
		buf_byte(&w.b, 0);
	}
	buf_byte(&w.b, (uint8_t)offsize);
	buf_byte(&w.b, (uint8_t)w.refsize);
	buf_be(&w.b, n, 8);
	buf_be(&w.b, top, 8);
	buf_be(&w.b, table, 8);
	free(w.offsets);
	*out = w.b.p;
	*len = w.b.len;
	return 0;
}

struct reader {
	const uint8_t *buf;
	size_t end;
	unsigned offsize;
	unsigned refsize;
	uint64_t nobjects;
	uint64_t table;
	size_t budget;
	size_t bytes;
};

static int
charge(struct reader *r, uint64_t n)
{
	if (n > r->bytes) {
		return -1;
	}
	r->bytes -= (size_t)n;
	return 0;
}

static uint64_t
get_be(const uint8_t *p, unsigned n)
{
	uint64_t v = 0;
	unsigned i;

	for (i = 0; i < n; i++) {
		v = (v << 8) | p[i];
	}
	return v;
}

static int
object_offset(struct reader *r, uint64_t ref, size_t *off)
{
	uint64_t o;

	if (ref >= r->nobjects) {
		return -1;
	}
	o = get_be(r->buf + r->table + ref * r->offsize, r->offsize);
	if (o < 8 || o >= r->end) {
		return -1;
	}
	*off = (size_t)o;
	return 0;
}

static int
read_length(struct reader *r, size_t *off, uint8_t marker, uint64_t *n)
{
	uint8_t m;
	unsigned size;

	if ((marker & 0x0F) != 0x0F) {
		*n = marker & 0x0F;
		return 0;
	}
	if (*off >= r->end) {
		return -1;
	}
	m = r->buf[(*off)++];
	if ((m & 0xF0) != 0x10 || (m & 0x0F) > 3) {
		return -1;
	}
	size = 1u << (m & 0x0F);
	if (*off + size > r->end) {
		return -1;
	}
	*n = get_be(r->buf + *off, size);
	*off += size;
	return 0;
}

static int
utf8_put(struct buf *b, uint32_t cp)
{
	uint8_t t[4];

	if (cp == 0) {
		return -1;
	}
	if (cp < 0x80) {
		t[0] = (uint8_t)cp;
		buf_put(b, t, 1);
	} else if (cp < 0x800) {
		t[0] = (uint8_t)(0xC0 | (cp >> 6));
		t[1] = (uint8_t)(0x80 | (cp & 0x3F));
		buf_put(b, t, 2);
	} else if (cp < 0x10000) {
		t[0] = (uint8_t)(0xE0 | (cp >> 12));
		t[1] = (uint8_t)(0x80 | ((cp >> 6) & 0x3F));
		t[2] = (uint8_t)(0x80 | (cp & 0x3F));
		buf_put(b, t, 3);
	} else {
		t[0] = (uint8_t)(0xF0 | (cp >> 18));
		t[1] = (uint8_t)(0x80 | ((cp >> 12) & 0x3F));
		t[2] = (uint8_t)(0x80 | ((cp >> 6) & 0x3F));
		t[3] = (uint8_t)(0x80 | (cp & 0x3F));
		buf_put(b, t, 4);
	}
	return 0;
}

static pl_t *read_object(struct reader *r, uint64_t ref, int depth);

static pl_t *
read_utf16(struct reader *r, size_t off, uint64_t units)
{
	struct buf b = { NULL, 0, 0 };
	uint64_t i;
	uint32_t c, lo;
	pl_t *p;

	if (units > (r->end - off) / 2 || charge(r, 3 * units + 1) != 0) {
		return NULL;
	}
	for (i = 0; i < units; i++) {
		c = (uint32_t)get_be(r->buf + off + 2 * i, 2);
		if (c >= 0xD800 && c <= 0xDBFF) {
			if (i + 1 >= units) {
				goto bad;
			}
			lo = (uint32_t)get_be(r->buf + off + 2 * (i + 1), 2);
			if (lo < 0xDC00 || lo > 0xDFFF) {
				goto bad;
			}
			c = 0x10000 + ((c - 0xD800) << 10) + (lo - 0xDC00);
			i++;
		} else if (c >= 0xDC00 && c <= 0xDFFF) {
			goto bad;
		}
		if (utf8_put(&b, c) != 0) {
			goto bad;
		}
	}
	p = pl_string_n(b.p ? (const char *)b.p : "", b.len);
	if (b.p != NULL) {
		od_wipe(b.p, b.len);
	}
	free(b.p);
	return p;
bad:
	if (b.p != NULL) {
		od_wipe(b.p, b.len);
	}
	free(b.p);
	return NULL;
}

static pl_t *
read_container(struct reader *r, size_t off, uint8_t marker, int depth)
{
	uint64_t n, i, kref, vref;
	pl_t *p, *k, *v;
	bool dict = (marker & 0xF0) == 0xD0;

	if (read_length(r, &off, marker, &n) != 0) {
		return NULL;
	}
	if (n > (r->end - off) / r->refsize / (dict ? 2 : 1) ||
	    charge(r, n * sizeof(pl_t *) * (dict ? 2 : 1)) != 0) {
		return NULL;
	}
	p = dict ? pl_dict() : pl_array();
	for (i = 0; i < n; i++) {
		if (dict) {
			kref = get_be(r->buf + off + i * r->refsize, r->refsize);
			vref = get_be(r->buf + off + (n + i) * r->refsize, r->refsize);
			k = read_object(r, kref, depth + 1);
			if (k == NULL || k->type != PL_STRING) {
				pl_free(k);
				pl_free(p);
				return NULL;
			}
			v = read_object(r, vref, depth + 1);
			if (v == NULL) {
				pl_free(k);
				pl_free(p);
				return NULL;
			}
			dict_append(p, (char *)k->bytes, v);
			k->bytes = NULL;
			k->len = 0;
			pl_free(k);
		} else {
			vref = get_be(r->buf + off + i * r->refsize, r->refsize);
			v = read_object(r, vref, depth + 1);
			if (v == NULL) {
				pl_free(p);
				return NULL;
			}
			pl_array_append(p, v);
		}
	}
	if (dict && has_duplicate_keys(p)) {
		pl_free(p);
		return NULL;
	}
	return p;
}

static pl_t *
read_object(struct reader *r, uint64_t ref, int depth)
{
	size_t off;
	uint8_t marker;
	uint64_t n, u;
	unsigned size;
	pl_t *p;
	double d;
	float f;

	if (depth > PL_MAX_DEPTH || r->budget == 0 || object_offset(r, ref, &off) != 0 ||
	    charge(r, sizeof(pl_t)) != 0) {
		return NULL;
	}
	r->budget--;
	marker = r->buf[off++];
	switch (marker & 0xF0) {
	case 0x00:
		if (marker == 0x08 || marker == 0x09) {
			return pl_bool(marker == 0x09);
		}
		return NULL;
	case 0x10:
		if ((marker & 0x0F) > 4) {
			return NULL;
		}
		size = 1u << (marker & 0x0F);
		if (off + size > r->end) {
			return NULL;
		}
		if (size == 16) {
			u = get_be(r->buf + off + 8, 8);
		} else {
			u = get_be(r->buf + off, size);
		}
		return pl_int((int64_t)u);
	case 0x20:
		if (marker == 0x22 && off + 4 <= r->end) {
			uint32_t w = (uint32_t)get_be(r->buf + off, 4);

			memcpy(&f, &w, 4);
			p = pl_new(PL_REAL);
			p->r = f;
			return p;
		}
		if (marker == 0x23 && off + 8 <= r->end) {
			u = get_be(r->buf + off, 8);
			memcpy(&d, &u, 8);
			p = pl_new(PL_REAL);
			p->r = d;
			return p;
		}
		return NULL;
	case 0x40:
	case 0x50:
		if (read_length(r, &off, marker, &n) != 0 || n > r->end - off || charge(r, n + 1) != 0) {
			return NULL;
		}
		if ((marker & 0xF0) == 0x40) {
			return pl_data(r->buf + off, (size_t)n);
		}
		if (memchr(r->buf + off, 0, (size_t)n) != NULL) {
			return NULL;
		}
		return pl_string_n((const char *)r->buf + off, (size_t)n);
	case 0x60:
		if (read_length(r, &off, marker, &n) != 0) {
			return NULL;
		}
		return read_utf16(r, off, n);
	case 0xA0:
	case 0xD0:
		return read_container(r, off, marker, depth);
	default:
		return NULL;
	}
}

pl_t *
pl_bplist_read(const uint8_t *buf, size_t len)
{
	struct reader r;
	const uint8_t *t;
	uint64_t top;

	if (buf == NULL || len < 8 + 32 || memcmp(buf, "bplist00", 8) != 0) {
		return NULL;
	}
	t = buf + len - 32;
	r.buf = buf;
	r.offsize = t[6];
	r.refsize = t[7];
	r.nobjects = get_be(t + 8, 8);
	top = get_be(t + 16, 8);
	r.table = get_be(t + 24, 8);
	r.budget = PL_MAX_NODES;
	r.bytes = len > (SIZE_MAX - PL_SLACK) / PL_EXPANSION ? SIZE_MAX : len * PL_EXPANSION + PL_SLACK;
	if (r.offsize < 1 || r.offsize > 8 || r.refsize < 1 || r.refsize > 8 || r.nobjects == 0 ||
	    top >= r.nobjects || r.table < 9 || r.table > len - 32 ||
	    r.nobjects > (len - 32 - r.table) / r.offsize) {
		return NULL;
	}
	r.end = (size_t)r.table;
	return read_object(&r, top, 0);
}
