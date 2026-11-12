/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 The Blueberry Pie OS Authors
 */
#ifndef TEST_SYS_KAUTH_H
#define TEST_SYS_KAUTH_H

#include <sys/types.h>

#include <stdint.h>

typedef uint8_t u_int8_t;
typedef uint32_t u_int32_t;
typedef uint64_t u_int64_t;

typedef union {
	unsigned char g_guid[16];
	unsigned int g_guid_asint[4];
} guid_t;

#define KAUTH_NTSID_MAX_AUTHORITIES 16
#pragma pack(1)
typedef struct {
	u_int8_t sid_kind;
	u_int8_t sid_authcount;
	u_int8_t sid_authority[6];
	u_int32_t sid_authorities[KAUTH_NTSID_MAX_AUTHORITIES];
} ntsid_t;
#pragma pack()
#define KAUTH_NTSID_HDRSIZE 8
#define KAUTH_NTSID_SIZE(_s) (KAUTH_NTSID_HDRSIZE + ((_s)->sid_authcount * sizeof(u_int32_t)))

struct kauth_identity_extlookup {
	u_int32_t el_seqno;
	u_int32_t el_result;
	u_int32_t el_flags;
	pid_t el_info_pid;
	u_int64_t el_extend;
	u_int32_t el_info_reserved_1;
	uid_t el_uid;
	guid_t el_uguid;
	u_int32_t el_uguid_valid;
	ntsid_t el_usid;
	u_int32_t el_usid_valid;
	gid_t el_gid;
	guid_t el_gguid;
	u_int32_t el_gguid_valid;
	ntsid_t el_gsid;
	u_int32_t el_gsid_valid;
	u_int32_t el_member_valid;
	u_int32_t el_sup_grp_cnt;
	gid_t el_sup_groups[16];
};

#define KAUTH_EXTLOOKUP_SUCCESS 0
#define KAUTH_EXTLOOKUP_BADRQ 1
#define KAUTH_EXTLOOKUP_FAILURE 2
#define KAUTH_EXTLOOKUP_FATAL 3
#define KAUTH_EXTLOOKUP_INPROG 100

#define KAUTH_EXTLOOKUP_VALID_UID (1 << 0)
#define KAUTH_EXTLOOKUP_VALID_UGUID (1 << 1)
#define KAUTH_EXTLOOKUP_VALID_USID (1 << 2)
#define KAUTH_EXTLOOKUP_VALID_GID (1 << 3)
#define KAUTH_EXTLOOKUP_VALID_GGUID (1 << 4)
#define KAUTH_EXTLOOKUP_VALID_GSID (1 << 5)
#define KAUTH_EXTLOOKUP_WANT_UID (1 << 6)
#define KAUTH_EXTLOOKUP_WANT_UGUID (1 << 7)
#define KAUTH_EXTLOOKUP_WANT_USID (1 << 8)
#define KAUTH_EXTLOOKUP_WANT_GID (1 << 9)
#define KAUTH_EXTLOOKUP_WANT_GGUID (1 << 10)
#define KAUTH_EXTLOOKUP_WANT_GSID (1 << 11)
#define KAUTH_EXTLOOKUP_WANT_MEMBERSHIP (1 << 12)
#define KAUTH_EXTLOOKUP_VALID_MEMBERSHIP (1 << 13)
#define KAUTH_EXTLOOKUP_ISMEMBER (1 << 14)
#define KAUTH_EXTLOOKUP_VALID_PWNAM (1 << 15)
#define KAUTH_EXTLOOKUP_WANT_PWNAM (1 << 16)
#define KAUTH_EXTLOOKUP_VALID_GRNAM (1 << 17)
#define KAUTH_EXTLOOKUP_WANT_GRNAM (1 << 18)
#define KAUTH_EXTLOOKUP_VALID_SUPGRPS (1 << 19)
#define KAUTH_EXTLOOKUP_WANT_SUPGRPS (1 << 20)

#define KAUTH_EXTLOOKUP_REGISTER 0
#define KAUTH_EXTLOOKUP_RESULT (1 << 0)
#define KAUTH_EXTLOOKUP_WORKER (1 << 1)
#define KAUTH_EXTLOOKUP_DEREGISTER (1 << 2)
#define KAUTH_GET_CACHE_SIZES (1 << 3)
#define KAUTH_SET_CACHE_SIZES (1 << 4)
#define KAUTH_CLEAR_CACHES (1 << 5)

#endif
