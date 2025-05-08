
/*
 * librfidx - Universal RFID Tag Format Parser and Converter
 *
 * Copyright (c) 2025. Firefox2100
 *
 * This software is released under the MIT License.
 * SPDX-License-Identifier: MIT
 */

#ifndef LIBRFIDX_MIFARE_COMMON_H
#define LIBRFIDX_MIFARE_COMMON_H

#include <stdint.h>

#define MFC_BLOCK_SIZE 16

#pragma pack(push, 1)
typedef union {
    uint8_t data[MFC_BLOCK_SIZE];
    struct {
        int32_t value;
        int32_t n_value;
        int32_t value_copy;
        uint8_t addr;
        uint8_t n_addr;
        uint8_t addr_copy;
        uint8_t n_addr_copy;
    } value;
} MfcBlock;
#pragma pack(pop)

_Static_assert(sizeof(MfcBlock) == MFC_BLOCK_SIZE, "Mifare Classic 1K block size mismatch");

#endif //LIBRFIDX_MIFARE_COMMON_H
