/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 The Blueberry Pie OS Authors
 */
#include <CommonCrypto/CommonKeyDerivation.h>

typedef struct evp_md_st EVP_MD;

const EVP_MD *EVP_sha512(void);
int PKCS5_PBKDF2_HMAC(const char *pass, int passlen, const unsigned char *salt, int saltlen,
    int iter, const EVP_MD *digest, int keylen, unsigned char *out);

int
CCKeyDerivationPBKDF(uint32_t algorithm, const char *password, size_t passwordLen,
    const uint8_t *salt, size_t saltLen, uint32_t prf, unsigned rounds, uint8_t *derivedKey,
    size_t derivedKeyLen)
{
	if (algorithm != kCCPBKDF2 || prf != kCCPRFHmacAlgSHA512 || rounds == 0) {
		return -1;
	}
	return PKCS5_PBKDF2_HMAC(password, (int)passwordLen, salt, (int)saltLen, (int)rounds,
	    EVP_sha512(), (int)derivedKeyLen, derivedKey) == 1 ? kCCSuccess : -1;
}
