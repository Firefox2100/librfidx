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
#include <stdbool.h>
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"

#define RFIDX_OK 0x00000000U
#define RFIDX_BINARY_FILE_IO_ERROR 0xFFFF0000U
#define RFIDX_BINARY_FILE_SIZE_ERROR 0xFFFF0001U
#define RFIDX_JSON_FILE_IO_ERROR 0xFFFF0002U
#define RFIDX_JSON_PARSE_ERROR 0xFFFF0003U
#define RFIDX_NUMERICAL_OPERATION_FAILED 0xFFFF0004U
#define RFIDX_NFC_FILE_IO_ERROR 0xFFFF0005U
#define RFIDX_NFC_PARSE_ERROR 0xFFFF0006U
#define RFIDX_FILE_FORMAT_ERROR 0xFFFF0007U
#define RFIDX_MEMORY_ERROR 0xFFFF0008U
#define RFIDX_DRNG_ERROR 0xFFFF0009U
#define RFIDX_UNKNOWN_ENUM_ERROR 0xFFFF0010U

#ifdef _WIN32
    #define RFIDX_EXPORT __declspec(dllexport)
#elif defined(__GNUC__) && __GNUC__ >= 4
    #define RFIDX_EXPORT __attribute__((visibility("default")))
#else
    #define RFIDX_EXPORT
#endif

typedef uint32_t RfidxStatus;

typedef enum {
    TAG_UNSPECIFIED = 0,
    NTAG_215,
    AMIIBO,
    TAG_UNKNOWN = -1,
    TAG_ERROR = -2,
} TagType;

typedef struct {
    const char *name;
    TagType value;
} TagTypeMap;

static const TagTypeMap tag_type_map[] = {
    {"amiibo", AMIIBO},
    {"ntag215", NTAG_215},
};

typedef enum {
    FORMAT_BINARY = 0,
    FORMAT_JSON,
    FORMAT_NFC,
    FORMAT_EML,
    FORMAT_UNKNOWN,
} FileFormat;

typedef enum {
    TRANSFORM_NONE = 0,
    TRANSFORM_GENERATE,
    TRANSFORM_RANDOMIZE_UID,
    TRANSFORM_WIPE,
} TransformCommand;

RFIDX_EXPORT extern mbedtls_ctr_drbg_context rfidx_ctr_drbg;
RFIDX_EXPORT extern mbedtls_entropy_context rfidx_entropy;
RFIDX_EXPORT extern bool rfidx_rng_initialized;

RFIDX_EXPORT RfidxStatus hex_to_bytes(const char *hex, uint8_t *out, size_t len);
RfidxStatus bytes_to_hex(const uint8_t *bytes, size_t len, char *out);
char* remove_whitespace(const char *str);
RFIDX_EXPORT TagType string_to_tag_type(const char *str);
RFIDX_EXPORT FileFormat string_to_file_format(const char *str);
void uint_to_str(unsigned int val, char *out, size_t out_size);
int appendf(char **buf, size_t *len, size_t *cap, const char *fmt, ...);
RFIDX_EXPORT int rfidx_init_rng(
    mbedtls_entropy_f_source_ptr custom_entropy_func,
    void *custom_entropy_param
);

#endif //LIBRFIDX_COMMON_H
