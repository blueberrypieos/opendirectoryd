/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 The Blueberry Pie OS Authors
 */
#ifndef TEST_COMMONKEYDERIVATION_H
#define TEST_COMMONKEYDERIVATION_H

#include <stddef.h>
#include <stdint.h>

#include <CommonCrypto/CommonCryptoError.h>

enum {
	kCCPBKDF2 = 2,
	kCCPRFHmacAlgSHA512 = 5,
};

int CCKeyDerivationPBKDF(uint32_t algorithm, const char *password, size_t passwordLen,
    const uint8_t *salt, size_t saltLen, uint32_t prf, unsigned rounds, uint8_t *derivedKey,
    size_t derivedKeyLen);

#endif
