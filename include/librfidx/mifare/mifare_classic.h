
/*
 * librfidx - Universal RFID Tag Format Parser and Converter
 *
 * Copyright (c) 2025. Firefox2100
 *
 * This software is released under the MIT License.
 * SPDX-License-Identifier: MIT
 */

#ifndef LIBRFIDX_MIFARE_CLASSIC_H
#define LIBRFIDX_MIFARE_CLASSIC_H

#include <stdint.h>
#include "librfidx/common.h"
#include "librfidx/mifare/mifare_common.h"

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
} MfcDataBlock;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct {
    uint8_t key_a[6];
    uint8_t access_bits[3];
    uint8_t user_data;
    uint8_t key_b[6];
} MfcSectorTrailer;
#pragma pack(pop)

typedef struct {
    uint8_t c1;
    uint8_t c2;
    uint8_t c3;
} MfcAccessBits;

MfcAccessBits mfc_get_access_bits_for_block(const MfcSectorTrailer *trailer, uint8_t block);
RfidxStatus mfc_set_access_bits_for_block(MfcSectorTrailer *trailer, uint8_t block, MfcAccessBits access_bits);
RfidxStatus mfc_validate_access_bits(const MfcAccessBits *access_bits);

_Static_assert(sizeof(MfcDataBlock) == MFC_BLOCK_SIZE, "Mifare Classic 1K block size mismatch");
_Static_assert(sizeof(MfcSectorTrailer) == MFC_BLOCK_SIZE, "Mifare Classic 1K sector trailer size mismatch");

#endif //LIBRFIDX_MIFARE_CLASSIC_H
