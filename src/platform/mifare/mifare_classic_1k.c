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
    FILE *file = fopen(filename, "wb");
    if (!file) return RFIDX_BINARY_FILE_IO_ERROR;

    uint8_t *buffer = mfc1k_serialize_binary(mfc1k, header);
    const size_t length = sizeof(Mfc1kData);

    if (fwrite(buffer, 1, length, file) != length) {
        free(buffer);
        fclose(file);
        return RFIDX_BINARY_FILE_IO_ERROR;
    }

    free(buffer);
    fclose(file);
    return RFIDX_OK;
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

    FILE *file = fopen(filename, "w");
    if (!file) {
        free(json_str);
        return RFIDX_JSON_FILE_IO_ERROR;
    }

    if (fputs(json_str, file) == EOF) {
        fclose(file);
        return RFIDX_JSON_FILE_IO_ERROR;
    }

    fclose(file);
    free(json_str);
    return RFIDX_OK;
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
    char *json_str = mfc1k_serialize_nfc(mfc1k, header);
    if (!json_str) {
        return RFIDX_JSON_PARSE_ERROR;
    }

    FILE *file = fopen(filename, "w");
    if (!file) {
        free(json_str);
        return RFIDX_JSON_FILE_IO_ERROR;
    }

    if (fputs(json_str, file) == EOF) {
        fclose(file);
        return RFIDX_JSON_FILE_IO_ERROR;
    }

    fclose(file);
    free(json_str);
    return RFIDX_OK;
}
