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

#define JSON_FORMAT_CREATOR "librfidx"

typedef uint32_t RfidxStatus;

/**
 * @brief Type of tags
 *
 * Used for identification and return values.
 */
typedef enum {
    TAG_UNSPECIFIED = 0,        /**< Unspecified tag type, instructing the program to deduct the type */
    NTAG_215,                   /**< NTAG 215 */
    MFC_1K,                     /**< Mifare Classic 1K */
    AMIIBO,                     /**< Nintendo Amiibo, an application level definition based on NTAG215 */
    TAG_UNKNOWN = -1,           /**< Cannot deduct the tag type */
    TAG_ERROR = -2,             /**< Error parsing the tag */
} TagType;

/**
 * @brief String to tag type mapping
 *
 * A mapping container for string converting to TagType enum.
 */
typedef struct {
    const char *name;           /**< Name in string format, from CLI parameter */
    TagType value;              /**< TagType enum value to map to */
} TagTypeMap;

static const TagTypeMap tag_type_map[] = {
    {"amiibo", AMIIBO},
    {"mfc1k", MFC_1K},
    {"ntag215", NTAG_215},
};

/**
 * @brief Format of a dump file
 *
 * Used for identification and return values.
 */
typedef enum {
    FORMAT_BINARY = 0,          /**< Binary dump */
    FORMAT_JSON,                /**< Proxmark latest JSON format dump */
    FORMAT_NFC,                 /**< Flipper Zero NFC format dump */
    FORMAT_EML,                 /**< Proxmark old EML format dump */
    FORMAT_UNKNOWN,             /**< Unknown format, cannot be deducted from the file content */
} FileFormat;

/**
 * @brief Transformation command
 *
 * Commands to instruct the program to transform the dump data.
 */
typedef enum {
    TRANSFORM_NONE = 0,         /**< No transformation. Data is exported as-is */
    TRANSFORM_GENERATE,         /**< Generate a new tag with empty data */
    TRANSFORM_RANDOMIZE_UID,    /**< Change the tag UID to a random one */
    TRANSFORM_WIPE,             /**< Wipe all data from the tag, turn it into a blank state */
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
RFIDX_EXPORT int rfidx_free_rng(void);

#endif //LIBRFIDX_COMMON_H
