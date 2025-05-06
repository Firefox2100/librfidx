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
#include <getopt.h>
#include "librfidx/rfidx.h"

TagType read_tag_from_file(const char *filename, const TagType input_type, void **data, void **header) {
    switch (input_type) {
        case NTAG_215:
            if (ntag215_read_from_file(filename, (Ntag215Data **)data, (Ntag21xMetadataHeader **)header) != RFIDX_OK) {
                fprintf(stderr, "NTAG215 data reading failed.\n");
                return TAG_ERROR;
            }
            return NTAG_215;
        default:
            return TAG_UNKNOWN;
    }
}

RfidxStatus save_tag_to_file(const void *data, const void *header, const TagType tag_type, const FileFormat output_format, const char *filename) {
    switch (tag_type) {
        case NTAG_215:
            char *buffer = transform_format((Ntag215Data*)data, (Ntag21xMetadataHeader*)header, output_format, filename);
            if (filename == NULL || strlen(filename) > 0) {
                if (buffer == NULL) {
                    fprintf(stderr, "Failed to transform NTAG215 data to %s format.\n", filename);
                    return RFIDX_NUMERICAL_OPERATION_FAILED;
                }

                printf("Tag data: \n%s\n", buffer);
            }
            if (buffer) free(buffer);
            return RFIDX_OK;
        default:
            return RFIDX_FILE_FORMAT_ERROR;
    }
}

static void usage(const char *executable_name) {
    fprintf(stderr,
        "rfidx by Firefox2100\n\n"
        "Usage: %s [-i input] [-I input type] [-o output -F output format]\n"
        "   -i/--input Input file path. If not needed (e.g. synthesising dump), can be omitted.\n"
        "   -o/--output Output file path. Omit to use stdout.\n"
        "   -I/--input-type Input tag type. Omit to automatically detect.\n"
        "   -F/--output-format Output format. Must be specified with -o option.\n",
        executable_name
    );
}

RfidxStatus main(const int argc, char ** argv) {
    const char *executable_name = argv[0];

    const char * input_file = NULL;
    const char * output_file = NULL;
    const char * input_type = NULL;
    const char * output_format = NULL;

    static struct option long_options[] = {
        {"input",         required_argument, 0, 'i'},
        {"input-type",  required_argument, 0,  'I' },
        {"output",        required_argument, 0, 'o'},
        {"output-format", required_argument, 0,  'F' },
        {0, 0, 0, 0}
    };

    int opt;
    int long_index = 0;

    while ((opt = getopt_long(argc, argv, "i:o:I:F:", long_options, &long_index)) != -1) {
        switch (opt) {
            case 'i':
                input_file = optarg;
                break;
            case 'o':
                output_file = optarg;
                break;
            case 'I':
                input_type = optarg;
                break;
            case 'F':
                output_format = optarg;
                break;
            default:
                usage(executable_name);
                exit(EXIT_FAILURE);
        }
    }

    // Validate the input parameters
    if (output_file != NULL && output_format == NULL) {
        fprintf(stderr, "Output format must be specified with -o option.\n");
        usage(executable_name);
        exit(EXIT_FAILURE);
    }
    TagType tag_type = TAG_UNSPECIFIED;
    if (input_type != NULL) {
        tag_type = string_to_tag_type(input_type);
        if (tag_type == TAG_UNKNOWN) {
            fprintf(stderr, "Unknown input type: %s\n", input_type);
            usage(executable_name);
            exit(EXIT_FAILURE);
        }
    }

    void * data = NULL;
    void * header = NULL;

    tag_type = read_tag_from_file(input_file, tag_type, &data, &header);
    if (tag_type == TAG_UNKNOWN) {
        fprintf(stderr, "Tag type not recognized or not supported; try again by manually specifying the type.\n");
        usage(executable_name);

        if (data) free(data);
        if (header) free(header);
        exit(EXIT_FAILURE);
    }
    if (tag_type == TAG_ERROR) {
        fprintf(stderr, "Failed to read tag data from file: %s\n", input_file);
        usage(executable_name);

        if (data) free(data);
        if (header) free(header);
        exit(EXIT_FAILURE);
    }

    if (output_format != NULL) {
        // Convert the input to output format
        const FileFormat format = string_to_file_format(output_format);
        if (format == FORMAT_UNKNOWN) {
            fprintf(stderr, "Unknown output format: %s\n", output_format);
            usage(executable_name);

            if (data) free(data);
            if (header) free(header);
            exit(EXIT_FAILURE);
        }

        return save_tag_to_file(data, header, tag_type, format, output_file);
    }

    return RFIDX_OK;
}
