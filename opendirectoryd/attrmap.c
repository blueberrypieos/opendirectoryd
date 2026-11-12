/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 The Blueberry Pie OS Authors
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "od.h"

struct attrmap {
	const char *attr;
	const char *key;
};

static const struct attrmap attrmap[] = {
	{ "AltSecurityIdentities", "altsecurityidentities" },
	{ "AuthenticationAuthority", "authentication_authority" },
	{ "AuthenticationHint", "hint" },
	{ "Building", "building" },
	{ "Change", "change" },
	{ "City", "city" },
	{ "Comment", "comment" },
	{ "Company", "company" },
	{ "Computers", "computers" },
	{ "Country", "country" },
	{ "CreationTimestamp", "creationtimestamp" },
	{ "Department", "department" },
	{ "EMailAddress", "mail" },
	{ "Expire", "expire" },
	{ "FAXNumber", "faxnumber" },
	{ "FirstName", "firstname" },
	{ "GeneratedUID", "generateduid" },
	{ "Group", "groups" },
	{ "GroupMembers", "groupmembers" },
	{ "GroupMembership", "users" },
	{ "HomeDirectory", "home_loc" },
	{ "HomeDirectoryQuota", "homedirectoryquota" },
	{ "HomeDirectorySoftQuota", "homedirectorysoftquota" },
	{ "HomeLocOwner", "home_loc_owner" },
	{ "HomePhoneNumber", "homephonenumber" },
	{ "IMHandle", "imhandle" },
	{ "JPEGPhoto", "jpegphoto" },
	{ "JobTitle", "jobtitle" },
	{ "Keywords", "keywords" },
	{ "LastName", "lastname" },
	{ "MiddleName", "middlename" },
	{ "MobileNumber", "mobilenumber" },
	{ "ModificationTimestamp", "modificationtimestamp" },
	{ "NFSHomeDirectory", "home" },
	{ "NestedGroups", "nestedgroups" },
	{ "NickName", "nickname" },
	{ "Note", "note" },
	{ "OrganizationName", "orgname" },
	{ "PagerNumber", "pagernumber" },
	{ "Password", "passwd" },
	{ "PasswordPolicyOptions", "passwordpolicyoptions" },
	{ "PhoneNumber", "phonenumber" },
	{ "Picture", "picture" },
	{ "PostalAddress", "postaladdress" },
	{ "PostalCode", "zip" },
	{ "PrimaryGroupID", "gid" },
	{ "RealName", "realname" },
	{ "RecordName", "name" },
	{ "SMBGroupRID", "smb_group_rid" },
	{ "SMBPrimaryGroupSID", "smb_primary_group_sid" },
	{ "SMBRID", "smb_rid" },
	{ "SMBSID", "smb_sid" },
	{ "State", "state" },
	{ "Street", "street" },
	{ "TimeToLive", "timetolive" },
	{ "URL", "URL" },
	{ "UniqueID", "uid" },
	{ "UserShell", "shell" },
};

static const char *const virtual_attrs[] = {
	OD_STD "RecordType",
	OD_STD "AppleMetaNodeLocation",
	OD_STD "AppleMetaRecordName",
};

#define NMAP (sizeof(attrmap) / sizeof(attrmap[0]))

bool
attr_is_virtual(const char *attr)
{
	size_t i;

	for (i = 0; i < sizeof(virtual_attrs) / sizeof(virtual_attrs[0]); i++) {
		if (strcmp(attr, virtual_attrs[i]) == 0) {
			return true;
		}
	}
	return false;
}

const char *
attr_key(const char *attr, bool *known)
{
	size_t i;

	*known = false;
	if (attr == NULL) {
		return NULL;
	}
	if (strncmp(attr, OD_NATIVE, strlen(OD_NATIVE)) == 0) {
		attr += strlen(OD_NATIVE);
		if (*attr == '\0' || strchr(attr, '/') != NULL) {
			return NULL;
		}
		*known = true;
		return attr;
	}
	if (strncmp(attr, OD_STD, strlen(OD_STD)) != 0) {
		return NULL;
	}
	attr += strlen(OD_STD);
	for (i = 0; i < NMAP; i++) {
		if (strcmp(attr, attrmap[i].attr) == 0) {
			*known = true;
			return attrmap[i].key;
		}
	}
	return NULL;
}

bool
attr_is_standard_key(const char *key)
{
	size_t i;

	for (i = 0; i < NMAP; i++) {
		if (strcmp(key, attrmap[i].key) == 0) {
			return true;
		}
	}
	return false;
}

char *
attr_name(const char *key)
{
	size_t i;
	char *s;

	for (i = 0; i < NMAP; i++) {
		if (strcmp(key, attrmap[i].key) == 0) {
			if (asprintf(&s, "%s%s", OD_STD, attrmap[i].attr) < 0) {
				abort();
			}
			return s;
		}
	}
	if (asprintf(&s, "%s%s", OD_NATIVE, key) < 0) {
		abort();
	}
	return s;
}
