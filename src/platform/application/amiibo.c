/*
 * librfidx - Universal RFID Tag Format Parser and Converter
 *
 * Copyright (c) 2025. Firefox2100
 *
 * This software is released under the MIT License.
 * SPDX-License-Identifier: MIT
 */

#include <stdio.h>
#include <string.h>
#include "mbedtls/aes.h"
#include "librfidx/application/amiibo.h"

RfidxStatus amiibo_load_dumped_keys(const char* filename, DumpedKeys *dumped_keys) {
    FILE * f = fopen(filename, "rb");

    if (!f) {
        return RFIDX_AMIIBO_KEY_IO_ERROR;
    }

    if (fread(dumped_keys, sizeof(DumpedKeys), 1, f) != 1) {
        fclose(f);
        return RFIDX_AMIIBO_KEY_IO_ERROR;
    }
    fclose(f);

    if (
        (dumped_keys->data.magicBytesSize > 16) ||
        (dumped_keys->tag.magicBytesSize > 16)
    ) {
        return RFIDX_AMIIBO_KEY_IO_ERROR;
    }

    return RFIDX_OK;
}

RfidxStatus amiibo_save_dumped_keys(const char* filename, const DumpedKeys* keys) {
    FILE * f = fopen(filename, "wb");

    if (!f) {
        return RFIDX_AMIIBO_KEY_IO_ERROR;
    }

    if (!fwrite(keys, sizeof(DumpedKeys), 1, f)) {
        fclose(f);

        return RFIDX_AMIIBO_KEY_IO_ERROR;
    }
    fclose(f);

    return RFIDX_OK;
}
