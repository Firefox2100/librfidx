/*
 * librfidx - Universal RFID Tag Format Parser and Converter
 *
 * Copyright (c) 2025. Firefox2100
 *
 * This software is released under the MIT License.
 * SPDX-License-Identifier: MIT
 */

#ifndef LIBRFIDX_COMMON_H
#define LIBRFIDX_COMMON_H

#include <stdint.h>

#define RFIDX_OK 0
#define RFIDX_BINARY_FILE_IO_ERROR -1
#define RFIDX_BINARY_FILE_SIZE_ERROR -2
#define RFIDX_JSON_FILE_IO_ERROR -3
#define RFIDX_JSON_PARSE_ERROR -4
#define RFIDX_NUMERICAL_OPERATION_FAILED -5
#define RFIDX_NFC_FILE_IO_ERROR -6
#define RFIDX_NFC_PARSE_ERROR -7

typedef uint32_t RfidxStatus;

RfidxStatus hex_to_bytes(const char *hex, uint8_t *out, size_t len);
RfidxStatus bytes_to_hex(const uint8_t *bytes, size_t len, char *out);
char* remove_whitespace(const char *str);

#endif //LIBRFIDX_COMMON_H
