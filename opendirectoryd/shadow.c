/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 The Blueberry Pie OS Authors
 */
#include <CommonCrypto/CommonCryptoError.h>
#include <CommonCrypto/CommonKeyDerivation.h>

#include <stdlib.h>
#include <string.h>

#include "od.h"

#define SHADOW_KIND "SALTED-SHA512-PBKDF2"
#define ENTROPY_LEN 128
#define SALT_LEN 32
#define MAX_ENTROPY 256
#define MAX_ITERATIONS 10000000

bool
od_consttime_equal(const uint8_t *a, const uint8_t *b, size_t len)
{
	volatile uint8_t d = 0;
	size_t i;

	for (i = 0; i < len; i++) {
		d |= a[i] ^ b[i];
	}
	return d == 0;
}

static int
derive(const char *password, size_t len, const uint8_t *salt, size_t saltlen, uint32_t iterations,
    uint8_t *out, size_t outlen)
{
	return CCKeyDerivationPBKDF(kCCPBKDF2, password, len, salt, saltlen, kCCPRFHmacAlgSHA512,
	    iterations, out, outlen) == kCCSuccess ? 0 : -1;
}

int
shadow_make(const char *password, size_t len, uint32_t iterations, uint8_t **out, size_t *outlen)
{
	uint8_t salt[SALT_LEN], entropy[ENTROPY_LEN];
	pl_t *top, *hash;
	int rc;

	if (iterations == 0 || iterations > MAX_ITERATIONS) {
		return -1;
	}
	arc4random_buf(salt, sizeof(salt));
	if (derive(password, len, salt, sizeof(salt), iterations, entropy, sizeof(entropy)) != 0) {
		return -1;
	}
	hash = pl_dict();
	pl_dict_set(hash, "entropy", pl_data(entropy, sizeof(entropy)));
	pl_dict_set(hash, "iterations", pl_int(iterations));
	pl_dict_set(hash, "salt", pl_data(salt, sizeof(salt)));
	top = pl_dict();
	pl_dict_set(top, SHADOW_KIND, hash);
	rc = pl_bplist_write(top, out, outlen);
	pl_free(top);
	od_wipe(entropy, sizeof(entropy));
	return rc;
}

int
shadow_verify(const uint8_t *shd, size_t len, const char *password, size_t pwlen)
{
	uint8_t derived[MAX_ENTROPY];
	const pl_t *hash, *entropy, *salt, *iter;
	pl_t *top;
	int rc = -1;

	top = pl_bplist_read(shd, len);
	hash = pl_dict_get(top, SHADOW_KIND);
	entropy = pl_dict_get(hash, "entropy");
	salt = pl_dict_get(hash, "salt");
	iter = pl_dict_get(hash, "iterations");
	if (pl_is(entropy, PL_DATA) && pl_is(salt, PL_DATA) && pl_is(iter, PL_INT) &&
	    entropy->len >= 16 && entropy->len <= MAX_ENTROPY && salt->len >= 8 && salt->len <= 1024 &&
	    iter->i >= 1 && iter->i <= MAX_ITERATIONS &&
	    derive(password, pwlen, salt->bytes, salt->len, (uint32_t)iter->i, derived, entropy->len) == 0) {
		rc = od_consttime_equal(derived, entropy->bytes, entropy->len) ? 1 : 0;
		od_wipe(derived, entropy->len);
	}
	pl_free(top);
	return rc;
}

void
shadow_dummy(const char *password, size_t len, uint32_t iterations)
{
	static const uint8_t salt[SALT_LEN];
	uint8_t entropy[ENTROPY_LEN];

	(void)derive(password, len, salt, sizeof(salt), iterations, entropy, sizeof(entropy));
	od_wipe(entropy, sizeof(entropy));
}
