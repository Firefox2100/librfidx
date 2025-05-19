/*
 * librfidx - Universal RFID Tag Format Parser and Converter
 *
 * Copyright (c) 2025. Firefox2100
 *
 * This software is released under the MIT License.
 * SPDX-License-Identifier: MIT
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdarg.h>
#include <ctype.h>
#include "librfidx/common.h"

mbedtls_ctr_drbg_context rfidx_ctr_drbg;
mbedtls_entropy_context rfidx_entropy;
bool rfidx_rng_initialized = false;

RfidxStatus hex_to_bytes(const char *hex, uint8_t *out, const size_t len) {
    if (!hex || !out) {
        return RFIDX_NUMERICAL_OPERATION_FAILED;
    }

    for (size_t i = 0; i < len; i++) {
        if (sscanf(hex + 2 * i, "%2hhx", &out[i]) != 1) {
            return RFIDX_NUMERICAL_OPERATION_FAILED;
        }
    }

    return RFIDX_OK;
}

RfidxStatus bytes_to_hex(const uint8_t *bytes, const size_t len, char *out) {
    if (!bytes || !out) {
        return RFIDX_NUMERICAL_OPERATION_FAILED;
    }

    for (size_t i = 0; i < len; i++) {
        if (sprintf(out + i * 2, "%02X", bytes[i]) < 0) {
            return RFIDX_NUMERICAL_OPERATION_FAILED;
        }
    }

    return RFIDX_OK;
}

char *remove_whitespace(const char *str) {
    if (!str) return NULL;

    const size_t len = strlen(str);
    char *result = malloc(len + 1);
    if (!result) return NULL;

    const char *read = str;
    char *write = result;

    while (*read) {
        if (!isspace((unsigned char)*read)) {
            *write++ = *read;
        }
        read++;
    }
    *write = '\0';

    return result;
}

static int compare_tag_type_map(const void *a, const void *b) {
    const TagTypeMap *key = a;
    const TagTypeMap *entry = b;
    return strcmp(key->name, entry->name);
}

TagType string_to_tag_type(const char *str) {
    const TagTypeMap key = { .name = str };
    const size_t map_size = sizeof(tag_type_map) / sizeof(tag_type_map[0]);

    const TagTypeMap *result = bsearch(&key, tag_type_map, map_size, sizeof(TagTypeMap), compare_tag_type_map);
    return result ? result->value : TAG_UNKNOWN;
}

FileFormat string_to_file_format(const char *str) {
    if (!str) return FORMAT_UNKNOWN;
    if (strcmp(str, "binary") == 0) return FORMAT_BINARY;
    if (strcmp(str, "json") == 0) return FORMAT_JSON;
    if (strcmp(str, "nfc") == 0) return FORMAT_NFC;
    if (strcmp(str, "eml") == 0) return FORMAT_EML;
    return FORMAT_UNKNOWN;
}

void uint_to_str(unsigned int val, char *out, const size_t out_size) {
    if (out_size == 0) return;

    out[out_size - 1] = '\0';  // ensure null-termination
    int pos = (int)out_size - 2;
    do {
        if (pos < 0) {
            out[0] = '\0'; // buffer too small
            return;
        }
        out[pos--] = (char)('0' + (val % 10));
        val /= 10;
    } while (val > 0);
    memmove(out, &out[pos + 1], out_size - pos - 1);
}

int appendf(char **buf, size_t *len, size_t *cap, const char *fmt, ...) {
    va_list args;
    while (1) {
        va_start(args, fmt);
        int needed = vsnprintf(*buf + *len, *cap - *len, fmt, args);
        va_end(args);

        if (needed < 0) return -1;

        if (*len + needed < *cap) {
            *len += needed;
            return 0;
        }

        const size_t new_cap = (*cap + needed + 1) * 2;
        char *new_buf = realloc(*buf, new_cap);
        if (!new_buf) return -1;

        *buf = new_buf;
        *cap = new_cap;
    }
}

int rfidx_init_rng(
    const mbedtls_entropy_f_source_ptr custom_entropy_func,
    void *custom_entropy_param
) {
    if (rfidx_rng_initialized) {
        return 0; // Already initialized. DO NOT REINITIALIZE.
    }

    const char *personalization = "rfidx_rng";
    mbedtls_entropy_init(&rfidx_entropy);
    mbedtls_ctr_drbg_init(&rfidx_ctr_drbg);

    if (custom_entropy_func) {
        mbedtls_entropy_add_source(
            &rfidx_entropy,
            custom_entropy_func,
            custom_entropy_param,
            32,
            MBEDTLS_ENTROPY_SOURCE_STRONG
        );
    }

    const int ret = mbedtls_ctr_drbg_seed(&rfidx_ctr_drbg,
        mbedtls_entropy_func,
        &rfidx_entropy,
        (const unsigned char *)personalization,
        strlen(personalization)
    );

    if (ret == 0) {
        rfidx_rng_initialized = true;
    } else {
        mbedtls_entropy_free(&rfidx_entropy);
        mbedtls_ctr_drbg_free(&rfidx_ctr_drbg);
    }

    return ret;
}
