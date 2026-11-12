/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 The Blueberry Pie OS Authors
 */
#include <stdlib.h>
#include <string.h>

#include "od.h"

#define FREE_FAILURES 5
#define MAX_DELAY 60
#define FORGET_AFTER (15 * 60)
#define MAX_ENTRIES 256

static unsigned
delay_for(unsigned count)
{
	unsigned shift;

	if (count < FREE_FAILURES) {
		return 0;
	}
	shift = count - FREE_FAILURES + 1;
	if (shift >= 6) {
		return MAX_DELAY;
	}
	return (1u << shift) < MAX_DELAY ? (1u << shift) : MAX_DELAY;
}

static bool
running(const struct fail *f, time_t now)
{
	unsigned d = delay_for(f->count);

	return d > 0 && now < f->last + d;
}

static bool
evictable(const struct fail *f, time_t now, bool known)
{
	return !running(f, now) && (!known || f->count < FREE_FAILURES);
}

static struct fails *
table(struct od *od, bool known)
{
	return known ? &od->known : &od->unknown;
}

static void
remove_at(struct fails *t, size_t i)
{
	free(t->e[i].name);
	t->e[i] = t->e[--t->count];
}

static void
expire(struct fails *t, time_t now)
{
	size_t i, j;

	for (i = 0, j = 0; i < t->count; i++) {
		if (now - t->e[i].last > FORGET_AFTER || now < t->e[i].last) {
			free(t->e[i].name);
		} else {
			t->e[j++] = t->e[i];
		}
	}
	t->count = j;
}

static struct fail *
lookup(struct fails *t, const char *name)
{
	size_t i;

	for (i = 0; i < t->count; i++) {
		if (strcmp(t->e[i].name, name) == 0) {
			return &t->e[i];
		}
	}
	return NULL;
}

static bool
make_room(struct fails *t, time_t now, bool known)
{
	size_t i, oldest = t->count;

	if (t->count >= MAX_ENTRIES) {
		for (i = 0; i < t->count; i++) {
			if (evictable(&t->e[i], now, known) && (oldest == t->count || t->e[i].last < t->e[oldest].last)) {
				oldest = i;
			}
		}
		if (oldest < t->count) {
			remove_at(t, oldest);
		} else if (!known) {
			return false;
		}
	}
	if (t->count == t->cap) {
		t->cap = t->cap ? t->cap * 2 : MAX_ENTRIES;
		t->e = realloc(t->e, t->cap * sizeof(*t->e));
		if (t->e == NULL) {
			abort();
		}
	}
	return true;
}

unsigned
backoff_remaining(struct od *od, const char *name, bool known)
{
	struct fails *t = table(od, known);
	time_t now = od->now();
	struct fail *f;

	expire(t, now);
	f = lookup(t, name);
	if (f == NULL || !running(f, now)) {
		return 0;
	}
	return (unsigned)(f->last + delay_for(f->count) - now);
}

void
backoff_failed(struct od *od, const char *name, bool known)
{
	struct fails *t = table(od, known);
	time_t now = od->now();
	struct fail *f;

	if (strnlen(name, OD_MAX_NAME + 1) > OD_MAX_NAME) {
		return;
	}
	expire(t, now);
	f = lookup(t, name);
	if (f == NULL) {
		if (!make_room(t, now, known)) {
			return;
		}
		f = &t->e[t->count++];
		f->name = strdup(name);
		if (f->name == NULL) {
			abort();
		}
		f->count = 0;
	}
	f->count++;
	f->last = now;
}

void
backoff_succeeded(struct od *od, const char *name)
{
	struct fail *f = lookup(&od->known, name);

	if (f != NULL) {
		remove_at(&od->known, (size_t)(f - od->known.e));
	}
}

void
backoff_free(struct od *od)
{
	struct fails *t[2] = { &od->known, &od->unknown };
	size_t i, j;

	for (i = 0; i < 2; i++) {
		for (j = 0; j < t[i]->count; j++) {
			free(t[i]->e[j].name);
		}
		free(t[i]->e);
		memset(t[i], 0, sizeof(*t[i]));
	}
}
