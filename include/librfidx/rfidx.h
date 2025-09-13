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

#define transform_format(data, header, output_format, filename)     \
    _Generic((data),                                                \
        Ntag215Data *: ntag215_transform_format,                    \
        const Ntag215Data *: ntag215_transform_format,              \
        default: unsupported_transform_format                       \
    )(data, header, output_format, filename)

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
