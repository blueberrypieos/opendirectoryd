/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 The Blueberry Pie OS Authors
 *
 * usage: opendirectoryd [-d]
 */
#include <sys/kauth.h>
#include <sys/stat.h>
#include <sys/syscall.h>

#include <bsm/audit.h>
#include <dispatch/dispatch.h>
#include <dlfcn.h>
#include <errno.h>
#include <notify.h>
#include <notify_keys.h>
#include <opendirectory/odipc.h>
#include <pthread.h>
#include <servers/bootstrap.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <xpc/private.h>
#include <xpc/xpc.h>

#include "od.h"

#define MAX_XPC_DEPTH 16
#define MAX_XPC_ENTRIES 1024
#define PIPE_BATCH 64

struct pipe_service {
	const char *name;
	pl_t *(*fn)(struct od *od, const char *proc, const pl_t *request);
	mach_port_t port;
	dispatch_source_t source;
};

struct api_reply {
	xpc_connection_t peer;
	uint64_t client_id;
};

static struct od od;
static struct od resolver_od;
static struct od_resolver resolver;
static dispatch_queue_t queue;
static bool foreground;

static void
log_message(int level, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	if (foreground) {
		fprintf(stderr, "opendirectoryd: ");
		vfprintf(stderr, fmt, ap);
		fputc('\n', stderr);
	} else {
		vsyslog(level, fmt, ap);
	}
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
	od_resolver_changed(&resolver);
	dispatch_after(dispatch_time(DISPATCH_TIME_NOW, NSEC_PER_SEC),
	    dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
		od_resolver_clear(&resolver);
	});
	notify_post(kNotifyDSCacheInvalidation);
	notify_post(kNotifyDSCacheInvalidationUser);
	notify_post(kNotifyDSCacheInvalidationGroup);
}

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
static int
call_identitysvc(int opcode, struct kauth_identity_extlookup *el)
{
	return syscall(SYS_identitysvc, opcode, el);
}
#pragma clang diagnostic pop

static void
resolver_pause(void)
{
	sleep(1);
}

static void *
resolver_thread(void *arg)
{
	od_resolver_run(arg);
	return NULL;
}

static void
resolver_start(void)
{
	pthread_t thread;
	int rc;

	rc = pthread_create(&thread, NULL, resolver_thread, &resolver);
	if (rc != 0) {
		log_message(LOG_ERR, "cannot start the identity resolver: %s", strerror(rc));
		return;
	}
	pthread_detach(thread);
}

static void
on_signal(int sig)
{
	dispatch_source_t s;

	signal(sig, SIG_IGN);
	s = dispatch_source_create(DISPATCH_SOURCE_TYPE_SIGNAL, (uintptr_t)sig, 0, queue);
	dispatch_source_set_event_handler(s, ^{
		od_resolver_stop(&resolver);
		exit(0);
	});
	dispatch_resume(s);
}

static xpc_object_t
to_xpc(const pl_t *p)
{
	xpc_object_t o, v;
	size_t i;

	switch (p->type) {
	case PL_DICT:
		o = xpc_dictionary_create(NULL, NULL, 0);
		for (i = 0; i < p->count; i++) {
			v = to_xpc(p->items[i]);
			if (v != NULL) {
				xpc_dictionary_set_value(o, p->keys[i], v);
				xpc_release(v);
			}
		}
		return o;
	case PL_ARRAY:
		o = xpc_array_create(NULL, 0);
		for (i = 0; i < p->count; i++) {
			v = to_xpc(p->items[i]);
			if (v != NULL) {
				xpc_array_append_value(o, v);
				xpc_release(v);
			}
		}
		return o;
	case PL_STRING:
		return xpc_string_create((const char *)p->bytes);
	case PL_DATA:
		return xpc_data_create(p->bytes, p->len);
	case PL_INT:
		return xpc_int64_create(p->i);
	case PL_BOOL:
		return xpc_bool_create(p->i != 0);
	case PL_REAL:
		return xpc_double_create(p->r);
	}
	return NULL;
}

static pl_t *
from_xpc(xpc_object_t o, int depth)
{
	xpc_type_t t = xpc_get_type(o);
	__block pl_t *p;

	if (depth > MAX_XPC_DEPTH) {
		return NULL;
	}
	if (t == XPC_TYPE_DICTIONARY) {
		if (xpc_dictionary_get_count(o) > MAX_XPC_ENTRIES) {
			return NULL;
		}
		p = pl_dict();
		xpc_dictionary_apply(o, ^bool(const char *key, xpc_object_t value) {
			pl_t *v = from_xpc(value, depth + 1);

			if (v != NULL) {
				pl_dict_set(p, key, v);
			}
			return true;
		});
		return p;
	}
	if (t == XPC_TYPE_ARRAY) {
		if (xpc_array_get_count(o) > MAX_XPC_ENTRIES) {
			return NULL;
		}
		p = pl_array();
		xpc_array_apply(o, ^bool(size_t index, xpc_object_t value) {
			pl_t *v = from_xpc(value, depth + 1);

			(void)index;
			if (v != NULL) {
				pl_array_append(p, v);
			}
			return true;
		});
		return p;
	}
	if (t == XPC_TYPE_STRING) {
		return pl_string(xpc_string_get_string_ptr(o));
	}
	if (t == XPC_TYPE_DATA) {
		return pl_data(xpc_data_get_bytes_ptr(o), xpc_data_get_length(o));
	}
	if (t == XPC_TYPE_UUID) {
		return pl_data(xpc_uuid_get_bytes(o), 16);
	}
	if (t == XPC_TYPE_INT64) {
		return pl_int(xpc_int64_get_value(o));
	}
	if (t == XPC_TYPE_UINT64) {
		return pl_int((int64_t)xpc_uint64_get_value(o));
	}
	if (t == XPC_TYPE_BOOL) {
		return pl_bool(xpc_bool_get_value(o));
	}
	return NULL;
}

static void
get_uuid(xpc_object_t msg, const char *key, uint8_t uu[16])
{
	xpc_object_t v = xpc_dictionary_get_value(msg, key);

	memset(uu, 0, 16);
	if (v != NULL && xpc_get_type(v) == XPC_TYPE_UUID) {
		memcpy(uu, xpc_uuid_get_bytes(v), 16);
	}
}

static void
api_send(void *ctx, uint64_t error, bool complete, const pl_t *reply)
{
	struct api_reply *r = ctx;
	xpc_object_t m = xpc_dictionary_create(NULL, NULL, 0);
	uint8_t *data;
	size_t len;

	xpc_dictionary_set_uint64(m, kODXPCReplyClientID, r->client_id);
	xpc_dictionary_set_uint64(m, kODXPCReplyError, error);
	xpc_dictionary_set_bool(m, kODXPCReplyComplete, complete);
	if (reply != NULL && pl_bplist_write(reply, &data, &len) == 0) {
		xpc_dictionary_set_data(m, kODXPCReplyData, data, len);
		od_wipe(data, len);
		free(data);
	}
	xpc_connection_send_message(r->peer, m);
	xpc_release(m);
}

static void
api_message(xpc_connection_t peer, xpc_object_t msg)
{
	struct api_reply r = { peer, xpc_dictionary_get_uint64(msg, kODXPCMessageClientID) };
	struct od_caller caller;
	uint8_t session[16], node[16];
	audit_token_t token;
	const void *data;
	size_t len = 0;

	xpc_dictionary_get_audit_token(msg, &token);
	caller.euid = (uid_t)token.val[1];
	caller.pid = (pid_t)token.val[5];
	caller.peer = peer;
	get_uuid(msg, kODXPCMessageSession, session);
	get_uuid(msg, kODXPCMessageNode, node);
	data = xpc_dictionary_get_data(msg, kODXPCMessageRequest, &len);
	od_api(&od, &caller, session, node, data, data != NULL ? len : 0, api_send, &r);
}

static void
api_peer(xpc_connection_t peer)
{
	xpc_retain(peer);
	xpc_connection_set_target_queue(peer, queue);
	xpc_connection_set_event_handler(peer, ^(xpc_object_t event) {
		if (xpc_get_type(event) == XPC_TYPE_DICTIONARY) {
			api_message(peer, event);
		} else if (event == XPC_ERROR_CONNECTION_INVALID) {
			od_peer_gone(&od, peer);
			xpc_release(peer);
		}
	});
	xpc_connection_resume(peer);
}

static void
api_start(void)
{
	xpc_connection_t listener;

	listener = xpc_connection_create_mach_service(kODAPIPortName, queue,
	    XPC_CONNECTION_MACH_SERVICE_LISTENER);
	if (listener == NULL) {
		log_message(LOG_ERR, "cannot create the %s listener", kODAPIPortName);
		exit(1);
	}
	xpc_connection_set_event_handler(listener, ^(xpc_object_t event) {
		if (xpc_get_type(event) == XPC_TYPE_CONNECTION) {
			api_peer(event);
		} else if (event == XPC_ERROR_CONNECTION_INVALID) {
			log_message(LOG_ERR, "cannot check in %s", kODAPIPortName);
			exit(1);
		}
	});
	xpc_connection_resume(listener);
}

static void
pipe_message(struct pipe_service *s, xpc_object_t msg)
{
	const char *proc = xpc_dictionary_get_string(msg, OD_RPC_NAME);
	xpc_object_t reply, v;
	pl_t *req, *res;
	size_t i;

	reply = xpc_dictionary_create_reply(msg);
	if (reply == NULL) {
		return;
	}
	req = from_xpc(msg, 0);
	res = s->fn(&od, proc, req);
	for (i = 0; i < res->count; i++) {
		v = to_xpc(res->items[i]);
		if (v != NULL) {
			xpc_dictionary_set_value(reply, res->keys[i], v);
			xpc_release(v);
		}
	}
	pl_free(req);
	pl_free(res);
	xpc_pipe_routine_reply(reply);
	xpc_release(reply);
}

static void
pipe_start(struct pipe_service *s)
{
	kern_return_t kr;

	kr = bootstrap_check_in(bootstrap_port, s->name, &s->port);
	if (kr != KERN_SUCCESS) {
		log_message(LOG_ERR, "cannot check in %s: %s", s->name, bootstrap_strerror(kr));
		exit(1);
	}
	s->source = dispatch_source_create(DISPATCH_SOURCE_TYPE_MACH_RECV, s->port, 0, queue);
	dispatch_source_set_event_handler(s->source, ^{
		xpc_object_t msg;
		int i, rc;

		for (i = 0; i < PIPE_BATCH; i++) {
			msg = NULL;
			rc = xpc_pipe_try_receive(s->port, &msg, NULL, NULL, 0, 0);
			if (rc == EAGAIN) {
				break;
			}
			if (rc != 0 || msg == NULL) {
				if (rc == EINVAL) {
					continue;
				}
				break;
			}
			pipe_message(s, msg);
			xpc_release(msg);
		}
	});
	dispatch_resume(s->source);
}

static void
usage(void)
{
	fprintf(stderr, "usage: opendirectoryd [-d]\n");
	exit(2);
}

int
main(int argc, char *argv[])
{
	static struct pipe_service libinfo = { kODMachLibinfoPortName, od_libinfo, MACH_PORT_NULL, NULL };
	static struct pipe_service membership = { kODMachMembershipPortName, od_membership,
		MACH_PORT_NULL, NULL };
	void (*disable)(void);
	int ch;

	while ((ch = getopt(argc, argv, "d")) != -1) {
		switch (ch) {
		case 'd':
			foreground = true;
			break;
		default:
			usage();
		}
	}
	if (optind != argc) {
		usage();
	}
	disable = (void (*)(void))dlsym(RTLD_DEFAULT, "_si_disable_opendirectory");
	if (disable != NULL) {
		disable();
	}
	openlog("opendirectoryd", LOG_PID | LOG_NDELAY, LOG_DAEMON);
	if (geteuid() != 0) {
		log_message(LOG_ERR, "must run as root");
		return 1;
	}
	umask(077);
	signal(SIGPIPE, SIG_IGN);
	od.shells_path = "/etc/shells";
	od.passwd_path = "/etc/passwd";
	od.master_passwd_path = "/etc/master.passwd";
	od.group_path = "/etc/group";
	od.iterations = OD_ITERATIONS;
	od.changed = changed;
	od.log = log_message;
	od.now = now;
	if (od_init(&od, OD_DEFAULT_ROOT) != 0 || od_init(&resolver_od, OD_DEFAULT_ROOT) != 0) {
		log_message(LOG_ERR, "cannot open %s: %s", OD_DEFAULT_ROOT, strerror(errno));
		return 1;
	}
	resolver_od.log = log_message;
	resolver_od.now = now;
	resolver.od = &resolver_od;
	resolver.svc = call_identitysvc;
	resolver.pause = resolver_pause;
	queue = dispatch_queue_create("org.blueberrypieos.opendirectoryd", NULL);
	dispatch_sync(queue, ^{
		on_signal(SIGTERM);
		on_signal(SIGINT);
		pipe_start(&libinfo);
		pipe_start(&membership);
		api_start();
	});
	log_message(LOG_NOTICE, "serving %s", OD_DEFAULT_ROOT);
	resolver_start();
	dispatch_main();
}
