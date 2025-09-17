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
#include <stdbool.h>
#include <cJSON.h>
#include <ctype.h>
#include <string.h>
#include "librfidx/mifare/mifare_classic_1k.h"
#include "librfidx/rfidx.h"

RfidxStatus mfc1k_load_from_binary(const char *filename, Mfc1kData *mfc1k, MfcMetadataHeader *header) {
    LOAD_FROM_BINARY_FILE(
        filename,
        mfc1k_parse_binary,
        mfc1k,
        Mfc1kData,
        header,
        MfcMetadataHeader,
        RFIDX_BINARY_FILE_IO_ERROR);
}

RfidxStatus mfc1k_save_to_binary(const char *filename, const Mfc1kData *mfc1k,
                                 const MfcMetadataHeader *header) {
    uint8_t *buffer = mfc1k_serialize_binary(mfc1k, header);
    const size_t length = sizeof(Mfc1kData);

    const RfidxStatus status = write_file(
        filename,
        (const char *) buffer,
        length,
        true,
        RFIDX_BINARY_FILE_IO_ERROR);
    free(buffer);
    return status;
}

RfidxStatus mfc1k_load_from_json(const char *filename, Mfc1kData *mfc1k, MfcMetadataHeader *header) {
    LOAD_FROM_TEXT_FILE(
        filename,
        mfc1k_parse_json,
        mfc1k,
        Mfc1kData,
        header,
        MfcMetadataHeader,
        RFIDX_JSON_FILE_IO_ERROR);
}

RfidxStatus mfc1k_save_to_json(const char *filename, const Mfc1kData *mfc1k,
                               const MfcMetadataHeader *header) {
    char *json_str = mfc1k_serialize_json(mfc1k, header);
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

RfidxStatus mfc1k_load_from_nfc(const char *filename, Mfc1kData *mfc1k, MfcMetadataHeader *header) {
    LOAD_FROM_TEXT_FILE(
        filename,
        mfc1k_parse_nfc,
        mfc1k,
        Mfc1kData,
        header,
        MfcMetadataHeader,
        RFIDX_NFC_FILE_IO_ERROR);
}

RfidxStatus mfc1k_save_to_nfc(
    const char *filename,
    const Mfc1kData *mfc1k,
    const MfcMetadataHeader *header
) {
    char *nfc_str = mfc1k_serialize_nfc(mfc1k, header);
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

char *mfc1k_transform_format(
    const Mfc1kData *mfc1k,
    const MfcMetadataHeader *header,
    const FileFormat output_format,
    const char *filename
) {
    TRANSFORM_FORMAT(
        filename,
        output_format,
        mfc1k,
        Mfc1kData,
        header,
        MfcMetadataHeader,
        sizeof(Mfc1kData),
        mfc1k_serialize_binary,
        mfc1k_save_to_binary,
        mfc1k_serialize_json,
        mfc1k_save_to_json,
        mfc1k_serialize_nfc,
        mfc1k_save_to_nfc
        );
}

RfidxStatus mfc1k_read_from_file(
    const char *filename,
    Mfc1kData **mfc1k,
    MfcMetadataHeader **header
) {
    // Determine the suffix of the file
    const char *suffix = strrchr(filename, '.');
    if (!suffix) {
        return RFIDX_FILE_FORMAT_ERROR;
    }
    if (strcmp(suffix, ".bin") == 0) {
        *mfc1k = malloc(sizeof(Mfc1kData));
        *header = malloc(sizeof(MfcMetadataHeader));
        return mfc1k_load_from_binary(filename, *mfc1k, *header);
    }

    if (strcmp(suffix, ".json") == 0) {
        *mfc1k = malloc(sizeof(Mfc1kData));
        *header = malloc(sizeof(MfcMetadataHeader));
        return mfc1k_load_from_json(filename, *mfc1k, *header);
    }

    if (strcmp(suffix, ".nfc") == 0) {
        *mfc1k = malloc(sizeof(Mfc1kData));
        *header = malloc(sizeof(MfcMetadataHeader));
        return mfc1k_load_from_nfc(filename, *mfc1k, *header);
    }

    return RFIDX_FILE_FORMAT_ERROR;
}
