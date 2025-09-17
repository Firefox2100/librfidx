/*
 * librfidx - Universal RFID Tag Format Parser and Converter
 *
 * Copyright (c) 2025. Firefox2100
 *
 * This software is released under the MIT License.
 * SPDX-License-Identifier: MIT
 */

#ifndef RFIDX_H
#define RFIDX_H

#include <stdio.h>
#include "librfidx/common.h"

#define transform_format(data, header, output_format, filename)     \
    _Generic((data),                                                \
        Ntag215Data *: ntag215_transform_format,                    \
        const Ntag215Data *: ntag215_transform_format,              \
        default: unsupported_transform_format                       \
    )(data, header, output_format, filename)

#define LOAD_FROM_TEXT_FILE(FILENAME, PARSE_FN, OUT_PTR, OUT_TYPE, HDR_PTR, HDR_TYPE, ERR_CODE) \
    do {                                                                                        \
        typedef RfidxStatus (*rfidx__parse_sig_t)(const char*, OUT_TYPE*, HDR_TYPE*);           \
        rfidx__parse_sig_t rfidx__pf = (PARSE_FN);                                              \
        (void)rfidx__pf;                                                                        \
                                                                                                \
        char *rfidx__buf = NULL;                                                                \
        RfidxStatus rfidx__st = read_file((FILENAME), &rfidx__buf, NULL, ERR_CODE);             \
        if (rfidx__st != RFIDX_OK) return rfidx__st;                                            \
                                                                                                \
        RfidxStatus rfidx__pst = rfidx__pf(rfidx__buf, (OUT_PTR), (HDR_PTR));                   \
        free(rfidx__buf);                                                                       \
        return rfidx__pst;                                                                      \
    } while (0)

#define LOAD_FROM_BINARY_FILE(FILENAME, PARSE_FN, OUT_PTR, OUT_TYPE, HDR_PTR, HDR_TYPE, ERR_CODE)       \
    do {                                                                                                \
        typedef RfidxStatus (*rfidx__parse_sig_t)(const uint8_t*, const size_t, OUT_TYPE*, HDR_TYPE*);  \
        rfidx__parse_sig_t rfidx__pf = (PARSE_FN);                                                      \
        (void)rfidx__pf;                                                                                \
                                                                                                        \
        char *rfidx__buf = NULL;                                                                        \
        size_t rfidx__buf_len = 0;                                                                      \
        RfidxStatus rfidx__st = read_file((FILENAME), &rfidx__buf, &rfidx__buf_len, ERR_CODE);          \
        if (rfidx__st != RFIDX_OK) return rfidx__st;                                                    \
                                                                                                        \
        RfidxStatus rfidx__pst = rfidx__pf(                                                             \
            (const uint8_t *)rfidx__buf, rfidx__buf_len, (OUT_PTR), (HDR_PTR));                         \
        free(rfidx__buf);                                                                               \
        return rfidx__pst;                                                                              \
    } while (0)

/**
 * @brief Dummy function for unsupported transformation format
 *
 * This function has no definition, as it is never meant to be called.
 * @param data Pointer to tag data to transform.
 * @param header Pointer to tag metadata header to transform.
 * @param output_format The selected output format.
 * @param filename File name as a string.
 * @return A NULL pointer if the file name is provided, or the output of the transformation.
 */
char *unsupported_transform_format(
    const void *data,
    const void *header,
    FileFormat output_format,
    const char *filename
);

RfidxStatus read_file(const char *filename, char **out_buf, size_t *out_len, uint32_t err_code);
RfidxStatus write_file(
    const char *filename,
    const char *buffer,
    size_t length,
    bool binary,
    uint32_t err_code
);

/**
 * @brief Read a tag from a given file path
 *
 * This function is the main utility function to read a tag from file system. If a tag type
 * is provided, it will respect that, and return an error if the type mismatch; if the type is
 * set to unspecified, it tries to determine the tag type from file, and return error if not
 * possible.
 * @param filename The file path to read the tag data from.
 * @param input_type The specified tag type. Set to TAG_UNSPECIFIED (0) to detect.
 * @param data The pointer to pointer of tag data, memory will be allocated WITHIN THE FUNCTION
 * if read successful. Must be freed after used.
 * @param header The pointer to pointer of metadata header, memory will be allocated WITHIN THE
 * FUNCTION if read successful. Must be freed after use.
 * @return The type of the tag. If return value is < 0, there is an error and the value must not
 * be used a valid type.
 */
TagType read_tag_from_file(
    const char *filename,
    TagType input_type,
    void **data,
    void **header
);

/**
 * @brief Main function for rfidx CLI utility
 *
 * This is the main function for rfidx CLI utility, separated from the main entry code for
 * easier testing and mocking.
 * @param argc Number of arguments from CLI.
 * @param argv Arguments from CLI.
 * @param output_stream The output stream for the program. This is also passed to inner functions.
 * @param error_stream The error stream for the program. This is also passed to inner functions.
 * @return RfidxStatus indicating success or failure of the main functions.
 */
RFIDX_EXPORT RfidxStatus rfidx_main(
    int argc,
    char ** argv,
    FILE *output_stream,
    FILE *error_stream
);

#endif //RFIDX_H
