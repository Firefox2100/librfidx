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
#include "librfidx/ntag/ntag215.h"
#include "librfidx/mifare/mifare_classic_1k.h"
#include "librfidx/application/amiibo.h"
#include "librfidx/rfidx.h"

RfidxStatus read_file(const char *filename, char **out_buf, size_t *out_len, const uint32_t err_code) {
    *out_buf = NULL;
    if (out_len) *out_len = 0;

    FILE *file = fopen(filename, "rb");
    if (!file) {
        return err_code;
    }

    if (fseek(file, 0, SEEK_END) != 0) {
        fclose(file);
        return err_code;
    }
    const long file_length = ftell(file);
    if (file_length < 0) {
        fclose(file);
        return err_code;
    }

    if (fseek(file, 0, SEEK_SET) != 0) {
        fclose(file);
        return err_code;
    }

    const size_t len = (size_t) file_length;
    char *buf = malloc(len + 1);
    if (!buf) {
        fclose(file);
        return RFIDX_MEMORY_ERROR;
    }

    const size_t rd = fread(buf, 1, len, file);
    fclose(file);

    if (rd != len) {
        free(buf);
        return err_code;
    }
    buf[len] = '\0';
    *out_buf = buf;

    if (out_len) *out_len = len;

    return RFIDX_OK;
}

RfidxStatus write_file(
    const char *filename,
    const char *buffer,
    const size_t length,
    const bool binary,
    const uint32_t err_code
) {
    FILE *file;
    if (binary) {
        file = fopen(filename, "wb");

        if (!file) {
            return err_code;
        }

        if (fwrite(buffer, 1, length, file) != length) {
            fclose(file);
            return RFIDX_BINARY_FILE_IO_ERROR;
        }
    } else {
        file = fopen(filename, "w");

        if (!file) {
            return err_code;
        }

        if (fputs(buffer, file) == EOF) {
            fclose(file);
            return err_code;
        }
    }

    fclose(file);
    return RFIDX_OK;
}

TagType read_tag_from_file(const char *filename, const TagType input_type, void **data, void **header) {
    switch (input_type) {
        case NTAG_215:
            if (ntag215_read_from_file(filename, (Ntag215Data **) data, (Ntag21xMetadataHeader **) header) !=
                RFIDX_OK) {
                fprintf(stderr, "NTAG215 data reading failed.\n");
                return TAG_ERROR;
            }
            return NTAG_215;
        case MFC_1K:
            if (mfc1k_read_from_file(filename, (Mfc1kData **) data, (MfcMetadataHeader **) header) !=
                RFIDX_OK) {
                fprintf(stderr, "Mfc1k data reading failed.\n");
                return TAG_ERROR;
            }
            return MFC_1K;
        case AMIIBO:
            if (ntag215_read_from_file(filename, (Ntag215Data **) data, (Ntag21xMetadataHeader **) header) !=
                RFIDX_OK) {
                fprintf(stderr, "Amiibo data reading failed.\n");
                return TAG_ERROR;
            }
            return AMIIBO;
        default:
            return TAG_UNKNOWN;
    }
}

RfidxStatus save_tag_to_file(
    const void *data,
    const void *header,
    const TagType tag_type,
    const FileFormat output_format,
    const char *filename,
    FILE *output_stream,
    FILE *error_stream
) {
    char *buffer;
    switch (tag_type) {
        case NTAG_215:
            buffer = transform_format((Ntag215Data*)data, (Ntag21xMetadataHeader*)header, output_format, filename);
            if (filename == NULL || strlen(filename) > 0) {
                if (buffer == NULL) {
                    fprintf(error_stream, "Failed to transform NTAG215 data to %s format.\n", filename);
                    return RFIDX_NUMERICAL_OPERATION_FAILED;
                }

                fprintf(output_stream, "Tag data: \n%s\n", buffer);
            }
            if (buffer) free(buffer);
            return RFIDX_OK;
        case MFC_1K:
            buffer = transform_format((Mfc1kData*)data, (MfcMetadataHeader*)header, output_format, filename);
            if (filename == NULL || strlen(filename) > 0) {
                if (buffer == NULL) {
                    fprintf(error_stream, "Failed to transform Mfc1k data to %s format.\n", filename);
                    return RFIDX_NUMERICAL_OPERATION_FAILED;
                }

                fprintf(output_stream, "Tag data: \n%s\n", buffer);
            }
            if (buffer) free(buffer);
            return RFIDX_OK;
        case AMIIBO:
            buffer = transform_format((Ntag215Data*)data, (Ntag21xMetadataHeader*)header, output_format, filename);
            if (filename == NULL || strlen(filename) > 0) {
                if (buffer == NULL) {
                    fprintf(error_stream, "Failed to transform Amiibo data to %s format.\n", filename);
                    return RFIDX_NUMERICAL_OPERATION_FAILED;
                }

                fprintf(output_stream, "Tag data: \n%s\n", buffer);
            }
            if (buffer) free(buffer);
            return RFIDX_OK;
        default:
            return RFIDX_FILE_FORMAT_ERROR;
    }
}

RfidxStatus transform_tag(
    const TagType tag_type,
    const TransformCommand command,
    void **data,
    void **header,
    const char *uuid,
    const char *retail_key
) {
    // Initialize the DRNG first
    rfidx_init_rng(NULL, NULL);

    switch (tag_type) {
        case NTAG_215:
            return ntag215_transform_data((Ntag215Data **) data, (Ntag21xMetadataHeader **) header, command);
        case MFC_1K:
            return mfc1k_transform_data((Mfc1kData **) data, (MfcMetadataHeader **) header, command);
        case AMIIBO:
            // Convert the uuid to uint8_t array
            uint8_t uuid_bytes[8] = {0};
            if (uuid) {
                if (hex_to_bytes(uuid, uuid_bytes, 8) != RFIDX_OK) {
                    fprintf(stderr, "Failed to convert UUID to bytes.\n");
                    return RFIDX_NUMERICAL_OPERATION_FAILED;
                }
            }

            // Load the retail key
            DumpedKeys dumped_keys = {0};
            if (retail_key) {
                if (amiibo_load_dumped_keys(retail_key, &dumped_keys) != RFIDX_OK) {
                    fprintf(stderr, "Failed to load retail key.\n");
                    return RFIDX_NUMERICAL_OPERATION_FAILED;
                }
            } else {
                fprintf(stderr, "Retail key is required for Amiibo transformation.\n");
                return RFIDX_NUMERICAL_OPERATION_FAILED;
            }

            return amiibo_transform_data(
                (AmiiboData **) data,
                (Ntag21xMetadataHeader **) header,
                command,
                uuid_bytes,
                &dumped_keys
            );
        default:
            return RFIDX_FILE_FORMAT_ERROR;
    }
}

static void usage(const char *executable_name, FILE *stream) {
    fprintf(stream,
            "rfidx by Firefox2100\n\n"
            "Usage: %s [-i <input-file-name>] [-I <input-type>] [-o <output-file-name> -F <output-format>] "
            "[-t <transform-command>] [-h]\n\n"
            "Standard options:\n"
            "   -i/--input <path> Input file path. If not needed (e.g. synthesising dump), can be omitted.\n"
            "   -o/--output <path> Output file path. Omit to use stdout.\n"
            "   -I/--input-type <type> Input tag type. Omit to automatically detect.\n"
            "   -F/--output-format <format> Output format. Must be specified with -o option.\n"
            "   -t/--transform <command> Transform command.\n"
            "   -h/--help Show this help message.\n\n"
            "Special parameters for different modes:\n"
            "   --uuid <UUID> Specify a UUID for the tag. This is used for generating a new "
            "Amiibo with given character information.\n"
            "   --retail-key <path> Specify a retail key for the tag. This is used for all "
            "Amiibo operations that require manipulation of the data.\n",
            executable_name
    );
}

TransformCommand string_to_transform_command(const char *str) {
    if (!str) return TRANSFORM_NONE;
    if (strcmp(str, "generate") == 0) return TRANSFORM_GENERATE;
    if (strcmp(str, "randomize-uid") == 0) return TRANSFORM_RANDOMIZE_UID;
    if (strcmp(str, "wipe") == 0) return TRANSFORM_WIPE;
    return TRANSFORM_NONE;
}

RfidxStatus rfidx_main(const int argc, char **argv, FILE *output_stream, FILE *error_stream) {
    const char *executable_name = argv[0];

    const char *input_file = NULL;
    const char *output_file = NULL;
    const char *input_type = NULL;
    const char *output_format = NULL;
    const char *transform_command = NULL;
    const char *uuid = NULL;
    const char *retail_key = NULL;

    static struct option long_options[] = {
        {"input", required_argument, 0, 'i'},
        {"input-type", required_argument, 0, 'I'},
        {"output", required_argument, 0, 'o'},
        {"output-format", required_argument, 0, 'F'},
        {"transform", required_argument, 0, 't'},
        {"help", no_argument, 0, 'h'},
        {"uuid", required_argument, 0, 1000},
        {"retail-key", required_argument, 0, 1001},
        {0, 0, 0, 0}
    };

    int opt;
    int long_index = 0;
    optind = 1; // Reset the index for getopt_long in case it's called multiple times

    while ((opt = getopt_long(argc, argv, "i:o:I:F:t:h", long_options, &long_index)) != -1) {
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
            case 't':
                transform_command = optarg;
                break;
            case 'h':
                usage(executable_name, output_stream);
                return EXIT_SUCCESS;
            case 1000:
                uuid = optarg;
                break;
            case 1001:
                retail_key = optarg;
                break;
            default:
                usage(executable_name, error_stream);
                return EXIT_FAILURE;
        }
    }

    // Validate the input parameters
    if (output_file != NULL && output_format == NULL) {
        fprintf(error_stream, "Output format must be specified with -o option.\n");
        usage(executable_name, error_stream);
        return EXIT_FAILURE;
    }
    TagType tag_type = TAG_UNSPECIFIED;
    if (input_type != NULL) {
        tag_type = string_to_tag_type(input_type);
        if (tag_type == TAG_UNKNOWN) {
            fprintf(error_stream, "Unknown input type: %s\n", input_type);
            usage(executable_name, error_stream);
            return EXIT_FAILURE;
        }
    }
    if (input_file == NULL) {
        if (input_type == NULL) {
            fprintf(
                error_stream,
                "Neither input file nor type is specified. "
                "Cannot proceed without knowing the tag type.\n"
            );
            usage(executable_name, error_stream);
            return EXIT_FAILURE;
        }
        if (transform_command == NULL) {
            fprintf(
                error_stream,
                "No input file or transform command specified. "
                "Does not know what to do.\n"
            );
            usage(executable_name, error_stream);
            return EXIT_FAILURE;
        }
    }

    void *data = NULL;
    void *header = NULL;

    if (input_file != NULL) {
        tag_type = read_tag_from_file(input_file, tag_type, &data, &header);
        if (tag_type == TAG_UNKNOWN) {
            fprintf(error_stream,
                    "Tag type not recognized or not supported; try again by manually specifying the type.\n");
            usage(executable_name, error_stream);

            if (data) free(data);
            if (header) free(header);
            return EXIT_FAILURE;
        }
        if (tag_type == TAG_ERROR) {
            fprintf(error_stream, "Failed to read tag data from file: %s\n", input_file);
            usage(executable_name, error_stream);

            if (data) free(data);
            if (header) free(header);
            return EXIT_FAILURE;
        }
    }

    TransformCommand command = TRANSFORM_NONE;
    if (transform_command != NULL) {
        command = string_to_transform_command(transform_command);

        if (command == TRANSFORM_NONE) {
            fprintf(error_stream, "Invalid transform_command specified.\n");
            usage(executable_name, error_stream);
            if (data) free(data);
            if (header) free(header);
            return EXIT_FAILURE;
        }

        if (transform_tag(tag_type, command, &data, &header, uuid, retail_key) != RFIDX_OK) {
            fprintf(error_stream, "Failed to transform tag data.\n");
            usage(executable_name, error_stream);

            if (data) free(data);
            if (header) free(header);
            return EXIT_FAILURE;
        }
    }

    if (output_format != NULL) {
        const FileFormat format = string_to_file_format(output_format);
        if (format == FORMAT_UNKNOWN) {
            fprintf(error_stream, "Unknown output format: %s\n", output_format);
            usage(executable_name, error_stream);

            if (data) free(data);
            if (header) free(header);
            return EXIT_FAILURE;
        }

        return save_tag_to_file(data, header, tag_type, format, output_file, output_stream, error_stream);
    }

    return RFIDX_OK;
}
