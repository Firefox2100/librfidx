/*
 * librfidx - Universal RFID Tag Format Parser and Converter
 *
 * Copyright (c) 2025. Firefox2100
 *
 * This software is released under the MIT License.
 * SPDX-License-Identifier: MIT
 */

#ifndef LIBRFIDX_MIFARE_CLASSIC_1K_CORE_H
#define LIBRFIDX_MIFARE_CLASSIC_1K_CORE_H

#include <stdint.h>
#include "librfidx/mifare/mifare_classic.h"

#define MFC_1K_BLOCK_SIZE MFC_BLOCK_SIZE
#define MFC_1K_NUM_BLOCK_PER_SECTOR 4
#define MFC_1K_NUM_SECTOR 16
#define MFC_1K_TOTAL_BYTES (MFC_1K_BLOCK_SIZE * MFC_1K_NUM_BLOCK_PER_SECTOR * MFC_1K_NUM_SECTOR)

typedef uint8_t Mfc1kRaw[MFC_1K_NUM_SECTOR][MFC_1K_NUM_BLOCK_PER_SECTOR][MFC_1K_BLOCK_SIZE];

#pragma pack(push, 1)
typedef union {
    Mfc1kRaw blocks;
    uint8_t bytes[MFC_1K_TOTAL_BYTES];
    struct {

    } structure;
} Mfc1kData;
#pragma pack(pop)

_Static_assert(sizeof(Mfc1kData) == MFC_1K_TOTAL_BYTES, "Mifare Classic 1K data size mismatch");

#endif //LIBRFIDX_MIFARE_CLASSIC_1K_CORE_H
