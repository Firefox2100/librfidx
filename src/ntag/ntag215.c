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

RfidxStatus ntag215_load_from_binary(const char *filename, Ntag215Data *ntag215, NtagSignature *signature) {
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
    } else if (filesize == sizeof(Ntag215Data) + sizeof(NtagSignature)) {
        // Contain both the dump and signature, dump first
        if (fread(ntag215, sizeof(Ntag215Data), 1, file) != 1) {
            fclose(file);
            return RFIDX_BINARY_FILE_IO_ERROR;
        }

        if (!fread(signature, sizeof(NtagSignature), 1, file)) {
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

RfidxStatus ntag215_save_to_binary(const char *filename, const Ntag215Data *ntag215, const NtagSignature *signature) {
    FILE *file = fopen(filename, "wb");

    if (!file) {
        return RFIDX_BINARY_FILE_IO_ERROR;
    }

    if (fwrite(ntag215, sizeof(Ntag215Data), 1, file) != 1) {
        fclose(file);
        return RFIDX_BINARY_FILE_IO_ERROR;
    }

    // If signature is not NULL or 0s, append it to the file
    const uint8_t empty_signature[NTAG_SIGNATURE_SIZE] = {0};
    if (signature && memcmp(signature, empty_signature, sizeof(NtagSignature)) != 0) {
        if (fwrite(signature, sizeof(NtagSignature), 1, file) != 1) {
            fclose(file);
            return RFIDX_BINARY_FILE_IO_ERROR;
        }
    }

    fclose(file);
    return RFIDX_OK;
}
