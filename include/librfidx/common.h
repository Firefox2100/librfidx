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
#define RFIDX_FILE_FORMAT_ERROR -8
#define RFIDX_MEMORY_ERROR -9

typedef uint32_t RfidxStatus;

typedef enum {
    TAG_UNSPECIFIED = 0,
    NTAG_215,
    TAG_UNKNOWN = -1,
    TAG_ERROR = -2,
} TagType;

typedef struct {
    const char *name;
    TagType value;
} TagTypeMap;

static const TagTypeMap tag_type_map[] = {
    {"ntag215", NTAG_215},
};

typedef enum {
    FORMAT_BINARY = 0,
    FORMAT_JSON,
    FORMAT_NFC,
    FORMAT_EML,
    FORMAT_UNKNOWN,
} FileFormat;

RfidxStatus hex_to_bytes(const char *hex, uint8_t *out, size_t len);
RfidxStatus bytes_to_hex(const uint8_t *bytes, size_t len, char *out);
char* remove_whitespace(const char *str);
TagType string_to_tag_type(const char *str);
FileFormat string_to_file_format(const char *str);
void uint_to_str(unsigned int val, char *out, size_t out_size);
int appendf(char **buf, size_t *len, size_t *cap, const char *fmt, ...);

#endif //LIBRFIDX_COMMON_H
