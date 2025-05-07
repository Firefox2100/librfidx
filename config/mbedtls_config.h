/*
* librfidx - Universal RFID Tag Format Parser and Converter
 *
 * Copyright (c) 2025. Firefox2100
 *
 * This software is released under the MIT License.
 * SPDX-License-Identifier: MIT
 */

#ifndef MBEDTLS_CONFIG_H
#define MBEDTLS_CONFIG_H

#define MBEDTLS_CIPHER_C
#define MBEDTLS_AES_C
#define MBEDTLS_AESNI_C
#define MBEDTLS_CIPHER_MODE_CTR
#define MBEDTLS_MD_C
#define MBEDTLS_SHA256_C
#define MBEDTLS_HAVE_SSE2
#define MBEDTLS_HAVE_ASM
#define MBEDTLS_PLATFORM_C

#endif //MBEDTLS_CONFIG_H
