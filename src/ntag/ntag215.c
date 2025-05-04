/*
 * librfidx - Universal RFID Tag Format Parser and Converter
 *
 * Copyright (c) 2025. Firefox2100
 *
 * This software is released under the MIT License.
 * SPDX-License-Identifier: MIT
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <librfidx/ntag/ntag215.h>

RfidxStatus ntag215_load_from_binary(const char *filename, Ntag215Data *ntag215, Ntag21xProxmarkHeader *header) {
    FILE *file = fopen(filename, "rb");

    // Open the file
    if (!file) {
        return RFIDX_BINARY_FILE_IO_ERROR;
    }

    // Check the file size
    if (fseek(file, 0, SEEK_END) != 0) {
        fclose(file);
        return RFIDX_BINARY_FILE_IO_ERROR;
    }
    const long filesize = ftell(file);
    if (filesize == -1L) {
        fclose(file);
        return RFIDX_BINARY_FILE_IO_ERROR;
    }

    // Rewind
    if (fseek(file, 0, SEEK_SET) != 0) {
        fclose(file);
        return RFIDX_BINARY_FILE_IO_ERROR;
    }

    if (filesize == sizeof(Ntag215Data)) {
        // Contain only the dump data
        if (!fread(ntag215, sizeof(Ntag215Data), 1, file)) {
            fclose(file);
            return RFIDX_BINARY_FILE_IO_ERROR;
        }
    } else if (filesize == sizeof(Ntag215Data) + sizeof(Ntag21xProxmarkHeader)) {
        // Contain both the dump and header, header first
        if (!fread(header, sizeof(Ntag21xProxmarkHeader), 1, file)) {
            fclose(file);
            return RFIDX_BINARY_FILE_IO_ERROR;
        }

        if (fread(ntag215, sizeof(Ntag215Data), 1, file) != 1) {
            fclose(file);
            return RFIDX_BINARY_FILE_IO_ERROR;
        }
    } else {
        fclose(file);
        return RFIDX_BINARY_FILE_SIZE_ERROR;
    }

    fclose(file);
    return RFIDX_OK;
}

RfidxStatus ntag215_save_to_binary(const char *filename, const Ntag215Data *ntag215, const Ntag21xProxmarkHeader *header) {
    FILE *file = fopen(filename, "wb");

    if (!file) {
        return RFIDX_BINARY_FILE_IO_ERROR;
    }

    // If header is not NULL or 0s, write it to the file first
    const uint8_t empty_header[sizeof(Ntag21xProxmarkHeader)] = {0};
    if (header && memcmp(header, empty_header, sizeof(Ntag21xProxmarkHeader)) != 0) {
        if (fwrite(header, sizeof(Ntag21xProxmarkHeader), 1, file) != 1) {
            fclose(file);
            return RFIDX_BINARY_FILE_IO_ERROR;
        }
    }

    if (fwrite(ntag215, sizeof(Ntag215Data), 1, file) != 1) {
        fclose(file);
        return RFIDX_BINARY_FILE_IO_ERROR;
    }

    fclose(file);
    return RFIDX_OK;
}
