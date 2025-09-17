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
#include <stdbool.h>
#include <cJSON.h>
#include <ctype.h>
#include "librfidx/ntag/ntag215.h"
#include "librfidx/rfidx.h"

RfidxStatus ntag215_load_from_binary(const char *filename, Ntag215Data *ntag215, Ntag21xMetadataHeader *header) {
    LOAD_FROM_BINARY_FILE(
        filename,
        ntag215_parse_binary,
        ntag215,
        Ntag215Data,
        header,
        Ntag21xMetadataHeader,
        RFIDX_BINARY_FILE_IO_ERROR);
}

RfidxStatus ntag215_save_to_binary(const char *filename, const Ntag215Data *ntag215,
                                   const Ntag21xMetadataHeader *header) {
    const uint8_t empty_header[sizeof(Ntag21xMetadataHeader)] = {0};
    uint8_t *buffer;
    size_t length;

    if (header && memcmp(header, empty_header, sizeof(Ntag21xMetadataHeader)) != 0) {
        buffer = ntag215_serialize_binary(ntag215, header);
        length = sizeof(Ntag21xMetadataHeader) + sizeof(Ntag215Data);
    } else {
        buffer = malloc(sizeof(Ntag215Data));
        if (!buffer) {
            return RFIDX_MEMORY_ERROR;
        }
        memcpy(buffer, ntag215, sizeof(Ntag215Data));
        length = sizeof(Ntag215Data);
    }

    const RfidxStatus status = write_file(
        filename,
        (const char *) buffer,
        length,
        true,
        RFIDX_BINARY_FILE_IO_ERROR);

    free(buffer);
    return status;
}

RfidxStatus ntag215_load_from_json(const char *filename, Ntag215Data *ntag215, Ntag21xMetadataHeader *header) {
    LOAD_FROM_TEXT_FILE(
        filename,
        ntag215_parse_json,
        ntag215,
        Ntag215Data,
        header,
        Ntag21xMetadataHeader,
        RFIDX_JSON_FILE_IO_ERROR);
}

RfidxStatus ntag215_save_to_json(const char *filename, const Ntag215Data *ntag215,
                                 const Ntag21xMetadataHeader *header) {
    char *json_str = ntag215_serialize_json(ntag215, header);
    if (!json_str) {
        return RFIDX_JSON_PARSE_ERROR;
    }

    const RfidxStatus status = write_file(
        filename,
        json_str,
        -1,
        false,
        RFIDX_JSON_FILE_IO_ERROR);
    free(json_str);
    return status;
}

RfidxStatus ntag215_load_from_nfc(const char *filename, Ntag215Data *ntag215, Ntag21xMetadataHeader *header) {
    LOAD_FROM_TEXT_FILE(
        filename,
        ntag215_parse_nfc,
        ntag215,
        Ntag215Data,
        header,
        Ntag21xMetadataHeader,
        RFIDX_NFC_FILE_IO_ERROR);
}

RfidxStatus ntag215_save_to_nfc(const char *filename, const Ntag215Data *ntag215, const Ntag21xMetadataHeader *header) {
    char *nfc_str = ntag215_serialize_nfc(ntag215, header);
    if (!nfc_str) {
        return RFIDX_NFC_PARSE_ERROR;
    }

    const RfidxStatus status = write_file(
        filename,
        nfc_str,
        -1,
        false,
        RFIDX_NFC_FILE_IO_ERROR);
    free(nfc_str);
    return status;
}

char *ntag215_transform_format(const Ntag215Data *data, const Ntag21xMetadataHeader *header,
                               const FileFormat output_format, const char *filename) {
    TRANSFORM_FORMAT(
        filename,
        output_format,
        data,
        Ntag215Data,
        header,
        Ntag21xMetadataHeader,
        sizeof(Ntag215Data) + sizeof(Ntag21xMetadataHeader),
        ntag215_serialize_binary,
        ntag215_save_to_binary,
        ntag215_serialize_json,
        ntag215_save_to_json,
        ntag215_serialize_nfc,
        ntag215_save_to_nfc
        );
}

RfidxStatus ntag215_read_from_file(const char *filename, Ntag215Data **data, Ntag21xMetadataHeader **header) {
    // Determine the suffix of the file
    const char *suffix = strrchr(filename, '.');
    if (!suffix) {
        return RFIDX_FILE_FORMAT_ERROR;
    }
    if (strcmp(suffix, ".bin") == 0) {
        *data = malloc(sizeof(Ntag215Data));
        *header = malloc(sizeof(Ntag21xMetadataHeader));
        return ntag215_load_from_binary(filename, *data, *header);
    }

    if (strcmp(suffix, ".json") == 0) {
        *data = malloc(sizeof(Ntag215Data));
        *header = malloc(sizeof(Ntag21xMetadataHeader));
        return ntag215_load_from_json(filename, *data, *header);
    }

    if (strcmp(suffix, ".nfc") == 0) {
        *data = malloc(sizeof(Ntag215Data));
        *header = malloc(sizeof(Ntag21xMetadataHeader));
        return ntag215_load_from_nfc(filename, *data, *header);
    }

    return RFIDX_FILE_FORMAT_ERROR;
}
