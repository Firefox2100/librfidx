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
#include <ctype.h>
#include "librfidx/common.h"

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

char* remove_whitespace(const char *str) {
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
