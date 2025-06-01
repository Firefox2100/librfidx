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

char *unsupported_transform_format(const void *data, const void *header, FileFormat output_format, const char *filename);

#define transform_format(data, header, output_format, filename)     \
    _Generic((data),                                                \
        Ntag215Data *: ntag215_transform_format,                    \
        const Ntag215Data *: ntag215_transform_format,              \
        default: unsupported_transform_format                       \
    )(data, header, output_format, filename)

TagType read_tag_from_file(const char *filename, TagType input_type, void **data, void **header);
RFIDX_EXPORT RfidxStatus rfidx_main(int argc, char ** argv, FILE *output_stream, FILE *error_stream);

#endif //RFIDX_H
