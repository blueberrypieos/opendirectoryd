/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 The Blueberry Pie OS Authors
 *
 * usage: dscl [-plist] node -read path [key ...]
 *        dscl [-plist] node -list path [key]
 *        dscl node -create path [key [value ...]]
 *        dscl node -append path key value ...
 *        dscl node -delete path [key [value ...]]
 *        dscl node -passwd path [new_password | old_password new_password]
 */
#include <CFOpenDirectory/CFOpenDirectory.h>
#include <CoreFoundation/CoreFoundation.h>
#include <readpassphrase.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "od.h"

static bool plist_output;
static const char *cmd_name;
static const char *path_arg;

static void
usage(void)
{
	fprintf(stderr,
	    "usage: dscl [-plist] node -read path [key ...]\n"
	    "       dscl [-plist] node -list path [key]\n"
	    "       dscl node -create path [key [value ...]]\n"
	    "       dscl node -append path key value ...\n"
	    "       dscl node -delete path [key [value ...]]\n"
	    "       dscl node -passwd path [new_password | old_password new_password]\n");
	exit(2);
}

static CFStringRef
cfstr(const char *s)
{
	CFStringRef r = CFStringCreateWithCString(NULL, s, kCFStringEncodingUTF8);

	if (r == NULL) {
		fprintf(stderr, "dscl: not UTF-8: %s\n", s);
		exit(1);
	}
	return r;
}

static char *
cstr(CFStringRef s)
{
	CFIndex n = CFStringGetMaximumSizeForEncoding(CFStringGetLength(s), kCFStringEncodingUTF8) + 1;
	char *buf = malloc((size_t)n);

	if (buf == NULL || !CFStringGetCString(s, buf, n, kCFStringEncodingUTF8)) {
		abort();
	}
	return buf;
}

static void
fail_error(CFErrorRef error)
{
	CFStringRef desc;
	char *d;

	if (error == NULL) {
		fprintf(stderr, "dscl: %s %s: failed\n", cmd_name, path_arg);
		exit(1);
	}
	desc = CFErrorCopyDescription(error);
	d = desc != NULL ? cstr(desc) : strdup("unknown error");
	fprintf(stderr, "dscl: %s %s: %s (error %ld)\n", cmd_name, path_arg, d, (long)CFErrorGetCode(error));
	exit(1);
}

static CFStringRef
attribute(const char *key)
{
	char buf[512];
	bool known;

	if (strncmp(key, OD_STD, strlen(OD_STD)) == 0 || strncmp(key, OD_NATIVE, strlen(OD_NATIVE)) == 0 ||
	    strncmp(key, "dsAttributes", 12) == 0) {
		return cfstr(key);
	}
	snprintf(buf, sizeof(buf), "%s%s", OD_STD, key);
	if (attr_is_virtual(buf) || (attr_key(buf, &known) != NULL && known)) {
		return cfstr(buf);
	}
	snprintf(buf, sizeof(buf), "%s%s", OD_NATIVE, key);
	return cfstr(buf);
}

static char *
short_name(CFStringRef attr)
{
	char *s = cstr(attr);

	if (strncmp(s, OD_STD, strlen(OD_STD)) == 0) {
		memmove(s, s + strlen(OD_STD), strlen(s) - strlen(OD_STD) + 1);
	}
	return s;
}

static ODNodeRef
open_node(const char *name)
{
	CFErrorRef error = NULL;
	CFStringRef n;
	ODNodeRef node;

	if (strcmp(name, ".") == 0 || strcmp(name, "localhost") == 0) {
		name = OD_LOCAL_NODE;
	}
	if (name[0] != '/') {
		fprintf(stderr, "dscl: %s: not a node\n", name);
		exit(1);
	}
	n = cfstr(name);
	node = ODNodeCreateWithName(NULL, kODSessionDefault, n, &error);
	CFRelease(n);
	if (node == NULL) {
		fail_error(error);
	}
	return node;
}

static bool
split_path(const char *path, CFStringRef *type, CFStringRef *name)
{
	char buf[512], *slash;

	*type = NULL;
	*name = NULL;
	if (path[0] != '/') {
		return false;
	}
	snprintf(buf, sizeof(buf), "%s", path + 1);
	while (strlen(buf) > 0 && buf[strlen(buf) - 1] == '/') {
		buf[strlen(buf) - 1] = '\0';
	}
	if (buf[0] == '\0') {
		return true;
	}
	slash = strchr(buf, '/');
	if (slash != NULL) {
		*slash++ = '\0';
		if (*slash == '\0' || strchr(slash, '/') != NULL) {
			return false;
		}
		*name = cfstr(slash);
	}
	if (strncmp(buf, "dsRecType", 9) == 0) {
		*type = cfstr(buf);
	} else {
		char t[600];

		snprintf(t, sizeof(t), "%s%s", OD_RECSTD, buf);
		*type = cfstr(t);
	}
	return true;
}

static ODRecordRef
copy_record(ODNodeRef node, CFStringRef type, CFStringRef name, CFTypeRef attrs)
{
	CFErrorRef error = NULL;
	ODRecordRef rec = ODNodeCopyRecord(node, type, name, attrs, &error);

	if (rec == NULL) {
		if (error != NULL) {
			fail_error(error);
		}
		fprintf(stderr, "dscl: %s %s: no such record\n", cmd_name, path_arg);
		exit(1);
	}
	return rec;
}

static void
write_plist(CFPropertyListRef p)
{
	CFDataRef data = CFPropertyListCreateData(NULL, p, kCFPropertyListXMLFormat_v1_0, 0, NULL);

	if (data == NULL) {
		fprintf(stderr, "dscl: cannot write the property list\n");
		exit(1);
	}
	fwrite(CFDataGetBytePtr(data), 1, (size_t)CFDataGetLength(data), stdout);
	CFRelease(data);
}

static bool
needs_lines(CFArrayRef values)
{
	CFIndex i;
	CFTypeRef v;
	char *s;
	bool lines = false;

	for (i = 0; i < CFArrayGetCount(values) && !lines; i++) {
		v = CFArrayGetValueAtIndex(values, i);
		if (CFGetTypeID(v) != CFStringGetTypeID()) {
			return true;
		}
		s = cstr(v);
		lines = s[0] == '\0' || strpbrk(s, " \t\n") != NULL;
		free(s);
	}
	return lines;
}

static void
print_value(CFTypeRef v)
{
	const UInt8 *b;
	CFIndex i, n;
	char *s;

	if (CFGetTypeID(v) == CFStringGetTypeID()) {
		s = cstr(v);
		fputs(s, stdout);
		free(s);
	} else if (CFGetTypeID(v) == CFDataGetTypeID()) {
		b = CFDataGetBytePtr(v);
		n = CFDataGetLength(v);
		for (i = 0; i < n; i++) {
			printf("%s%02x", i > 0 && i % 4 == 0 ? " " : "", b[i]);
		}
	} else if (CFGetTypeID(v) == CFNumberGetTypeID()) {
		long long x = 0;

		CFNumberGetValue(v, kCFNumberLongLongType, &x);
		printf("%lld", x);
	}
}

static void
print_attribute(CFStringRef attr, CFArrayRef values)
{
	char *name = short_name(attr);
	CFIndex i;

	printf("%s:", name);
	free(name);
	if (CFArrayGetCount(values) == 0) {
		putchar('\n');
		return;
	}
	if (needs_lines(values)) {
		putchar('\n');
		for (i = 0; i < CFArrayGetCount(values); i++) {
			putchar(' ');
			print_value(CFArrayGetValueAtIndex(values, i));
			putchar('\n');
		}
	} else {
		for (i = 0; i < CFArrayGetCount(values); i++) {
			putchar(' ');
			print_value(CFArrayGetValueAtIndex(values, i));
		}
		putchar('\n');
	}
}

static CFComparisonResult
compare_strings(const void *a, const void *b, void *ctx)
{
	(void)ctx;
	return CFStringCompare(a, b, 0);
}

static int
cmd_read(ODNodeRef node, CFStringRef type, CFStringRef name, int argc, char **argv)
{
	CFMutableArrayRef want = CFArrayCreateMutable(NULL, 0, &kCFTypeArrayCallBacks);
	CFErrorRef error = NULL;
	CFDictionaryRef details;
	CFMutableArrayRef keys;
	ODRecordRef rec;
	CFStringRef a;
	CFIndex i, n;
	int rc = 0;

	if (name == NULL) {
		usage();
	}
	if (argc == 0) {
		CFArrayAppendValue(want, CFSTR(OD_ATTR_ALL));
	}
	for (i = 0; i < argc; i++) {
		a = attribute(argv[i]);
		CFArrayAppendValue(want, a);
		CFRelease(a);
	}
	rec = copy_record(node, type, name, want);
	details = ODRecordCopyDetails(rec, argc == 0 ? NULL : want, &error);
	if (details == NULL) {
		fail_error(error);
	}
	for (i = 0; i < argc; i++) {
		if (!CFDictionaryContainsKey(details, CFArrayGetValueAtIndex(want, i))) {
			fprintf(stderr, "No such key: %s\n", argv[i]);
			rc = 1;
		}
	}
	if (plist_output) {
		write_plist(details);
	} else {
		n = CFDictionaryGetCount(details);
		keys = CFArrayCreateMutable(NULL, n, &kCFTypeArrayCallBacks);
		{
			const void **k = malloc((size_t)(n + 1) * sizeof(*k));

			CFDictionaryGetKeysAndValues(details, k, NULL);
			for (i = 0; i < n; i++) {
				CFArrayAppendValue(keys, k[i]);
			}
			free(k);
		}
		CFArraySortValues(keys, CFRangeMake(0, n), compare_strings, NULL);
		for (i = 0; i < n; i++) {
			CFTypeRef v = CFDictionaryGetValue(details, CFArrayGetValueAtIndex(keys, i));

			if (v != NULL && CFGetTypeID(v) == CFArrayGetTypeID()) {
				print_attribute(CFArrayGetValueAtIndex(keys, i), v);
			}
		}
		CFRelease(keys);
	}
	CFRelease(details);
	CFRelease(rec);
	CFRelease(want);
	return rc;
}

static CFComparisonResult
compare_records(const void *a, const void *b, void *ctx)
{
	(void)ctx;
	return CFStringCompare(ODRecordGetRecordName((ODRecordRef)a), ODRecordGetRecordName((ODRecordRef)b), 0);
}

static int
cmd_list(ODNodeRef node, CFStringRef type, CFStringRef name, int argc, char **argv)
{
	CFMutableArrayRef sorted, out;
	CFErrorRef error = NULL;
	CFArrayRef results, values;
	CFStringRef attr = NULL;
	ODQueryRef query;
	ODRecordRef rec;
	CFIndex i, n;
	size_t width = 0;
	char *s;

	if (name != NULL || argc > 1) {
		usage();
	}
	if (type == NULL) {
		if (plist_output) {
			CFStringRef t[2] = { CFSTR("Groups"), CFSTR("Users") };
			CFArrayRef a = CFArrayCreate(NULL, (const void **)t, 2, &kCFTypeArrayCallBacks);

			write_plist(a);
			CFRelease(a);
		} else {
			printf("Groups\nUsers\n");
		}
		return 0;
	}
	if (argc == 1) {
		attr = attribute(argv[0]);
	}
	query = ODQueryCreateWithNode(NULL, node, type, NULL, kODMatchAny, NULL, attr, 0, &error);
	if (query == NULL) {
		fail_error(error);
	}
	results = ODQueryCopyResults(query, false, &error);
	if (results == NULL) {
		if (error != NULL) {
			fail_error(error);
		}
		results = CFArrayCreate(NULL, NULL, 0, &kCFTypeArrayCallBacks);
	}
	n = CFArrayGetCount(results);
	sorted = CFArrayCreateMutableCopy(NULL, n, results);
	CFArraySortValues(sorted, CFRangeMake(0, n), compare_records, NULL);
	for (i = 0; i < n; i++) {
		s = cstr(ODRecordGetRecordName((ODRecordRef)CFArrayGetValueAtIndex(sorted, i)));
		if (strlen(s) > width) {
			width = strlen(s);
		}
		free(s);
	}
	out = CFArrayCreateMutable(NULL, n, &kCFTypeArrayCallBacks);
	for (i = 0; i < n; i++) {
		rec = (ODRecordRef)CFArrayGetValueAtIndex(sorted, i);
		values = attr != NULL ? ODRecordCopyValues(rec, attr, NULL) : NULL;
		if (plist_output) {
			CFMutableDictionaryRef d = CFDictionaryCreateMutable(NULL, 0,
			    &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
			CFArrayRef names = ODRecordCopyValues(rec, kODAttributeTypeRecordName, NULL);

			if (names != NULL) {
				CFDictionarySetValue(d, kODAttributeTypeRecordName, names);
				CFRelease(names);
			}
			if (values != NULL) {
				CFDictionarySetValue(d, attr, values);
			}
			CFArrayAppendValue(out, d);
			CFRelease(d);
		} else {
			s = cstr(ODRecordGetRecordName(rec));
			if (attr == NULL) {
				printf("%s\n", s);
			} else {
				CFIndex j;

				printf("%-*s", (int)width + 1, s);
				for (j = 0; values != NULL && j < CFArrayGetCount(values); j++) {
					if (j > 0) {
						putchar(' ');
					}
					print_value(CFArrayGetValueAtIndex(values, j));
				}
				putchar('\n');
			}
			free(s);
		}
		if (values != NULL) {
			CFRelease(values);
		}
	}
	if (plist_output) {
		write_plist(out);
	}
	CFRelease(out);
	CFRelease(sorted);
	CFRelease(results);
	CFRelease(query);
	if (attr != NULL) {
		CFRelease(attr);
	}
	return 0;
}

static CFArrayRef
value_array(int argc, char **argv)
{
	CFMutableArrayRef a = CFArrayCreateMutable(NULL, argc, &kCFTypeArrayCallBacks);
	CFStringRef s;
	int i;

	for (i = 0; i < argc; i++) {
		s = cfstr(argv[i]);
		CFArrayAppendValue(a, s);
		CFRelease(s);
	}
	return a;
}

static int
cmd_create(ODNodeRef node, CFStringRef type, CFStringRef name, int argc, char **argv)
{
	CFErrorRef error = NULL;
	CFStringRef attr;
	CFArrayRef values;
	ODRecordRef rec;
	char *empty[] = { (char *)"" };

	if (name == NULL) {
		usage();
	}
	rec = ODNodeCopyRecord(node, type, name, NULL, &error);
	if (rec == NULL) {
		if (error != NULL) {
			fail_error(error);
		}
		rec = ODNodeCreateRecord(node, type, name, NULL, &error);
		if (rec == NULL) {
			fail_error(error);
		}
	}
	if (argc > 0) {
		attr = attribute(argv[0]);
		values = argc > 1 ? value_array(argc - 1, argv + 1) : value_array(1, empty);
		if (!ODRecordSetValue(rec, attr, values, &error)) {
			fail_error(error);
		}
		CFRelease(values);
		CFRelease(attr);
	}
	CFRelease(rec);
	return 0;
}

static int
cmd_append(ODNodeRef node, CFStringRef type, CFStringRef name, int argc, char **argv)
{
	CFErrorRef error = NULL;
	CFStringRef attr, v;
	ODRecordRef rec;
	int i;

	if (name == NULL || argc < 2) {
		usage();
	}
	rec = copy_record(node, type, name, NULL);
	attr = attribute(argv[0]);
	for (i = 1; i < argc; i++) {
		v = cfstr(argv[i]);
		if (!ODRecordAddValue(rec, attr, v, &error)) {
			fail_error(error);
		}
		CFRelease(v);
	}
	CFRelease(attr);
	CFRelease(rec);
	return 0;
}

static int
cmd_delete(ODNodeRef node, CFStringRef type, CFStringRef name, int argc, char **argv)
{
	CFErrorRef error = NULL;
	CFStringRef attr, v;
	CFArrayRef none;
	ODRecordRef rec;
	int i;

	if (name == NULL) {
		usage();
	}
	rec = copy_record(node, type, name, NULL);
	if (argc == 0) {
		if (!ODRecordDelete(rec, &error)) {
			fail_error(error);
		}
		CFRelease(rec);
		return 0;
	}
	attr = attribute(argv[0]);
	if (argc == 1) {
		none = CFArrayCreate(NULL, NULL, 0, &kCFTypeArrayCallBacks);
		if (!ODRecordSetValue(rec, attr, none, &error)) {
			fail_error(error);
		}
		CFRelease(none);
	}
	for (i = 1; i < argc; i++) {
		v = cfstr(argv[i]);
		if (!ODRecordRemoveValue(rec, attr, v, &error)) {
			fail_error(error);
		}
		CFRelease(v);
	}
	CFRelease(attr);
	CFRelease(rec);
	return 0;
}

static char *
ask(const char *prompt)
{
	char buf[1024];

	if (readpassphrase(prompt, buf, sizeof(buf), RPP_ECHO_OFF | RPP_REQUIRE_TTY) == NULL) {
		fprintf(stderr, "dscl: cannot read the password\n");
		exit(1);
	}
	return strdup(buf);
}

static int
cmd_passwd(ODNodeRef node, CFStringRef type, CFStringRef name, int argc, char **argv)
{
	CFErrorRef error = NULL;
	CFStringRef oldp = NULL, newp;
	ODRecordRef rec;
	char *o = NULL, *n, *again;

	if (name == NULL || argc > 2) {
		usage();
	}
	if (argc == 0) {
		if (geteuid() != 0) {
			o = ask("Old Password:");
		}
		n = ask("New Password:");
		again = ask("Retype New Password:");
		if (strcmp(n, again) != 0) {
			fprintf(stderr, "dscl: the passwords differ\n");
			return 1;
		}
		free(again);
	} else if (argc == 1) {
		n = argv[0];
	} else {
		o = argv[0];
		n = argv[1];
	}
	rec = copy_record(node, type, name, NULL);
	if (o != NULL) {
		oldp = cfstr(o);
	}
	newp = cfstr(n);
	if (!ODRecordChangePassword(rec, oldp, newp, &error)) {
		fail_error(error);
	}
	if (oldp != NULL) {
		CFRelease(oldp);
	}
	CFRelease(newp);
	CFRelease(rec);
	return 0;
}

int
main(int argc, char *argv[])
{
	static const struct {
		const char *name;
		int (*fn)(ODNodeRef, CFStringRef, CFStringRef, int, char **);
		bool plist;
	} cmds[] = {
		{ "read", cmd_read, true },
		{ "list", cmd_list, true },
		{ "create", cmd_create, false },
		{ "append", cmd_append, false },
		{ "delete", cmd_delete, false },
		{ "passwd", cmd_passwd, false },
	};
	CFStringRef type, name;
	ODNodeRef node;
	const char *c;
	size_t i;
	int rc;

	argv++;
	argc--;
	if (argc > 0 && strcmp(argv[0], "-plist") == 0) {
		plist_output = true;
		argv++;
		argc--;
	}
	if (argc < 3) {
		usage();
	}
	c = argv[1][0] == '-' ? argv[1] + 1 : argv[1];
	for (i = 0; i < sizeof(cmds) / sizeof(cmds[0]); i++) {
		if (strcmp(c, cmds[i].name) == 0) {
			break;
		}
	}
	if (i == sizeof(cmds) / sizeof(cmds[0]) || (plist_output && !cmds[i].plist)) {
		usage();
	}
	cmd_name = argv[1];
	path_arg = argv[2];
	if (!split_path(argv[2], &type, &name) || (type == NULL && cmds[i].fn != cmd_list)) {
		fprintf(stderr, "dscl: %s: not a record path\n", argv[2]);
		return 1;
	}
	node = open_node(argv[0]);
	rc = cmds[i].fn(node, type, name, argc - 3, argv + 3);
	CFRelease(node);
	return rc;
}
