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
        Mfc4BlockSector sector[MFC_1K_NUM_SECTOR];
    } structure;
    MfcManufacturerData4B manufacturer_data_4b;
    MfcManufacturerData7B manufacturer_data_7b;
} Mfc1kData;
#pragma pack(pop)

RfidxStatus mfc1k_parse_binary(
    const uint8_t *buffer,
    Mfc1kData *mfc1k,
    MfcMetadataHeader *header
);

uint8_t *mfc1k_serialize_binary(
    const Mfc1kData *mfc1k,
    const MfcMetadataHeader *header
);

RfidxStatus mfc1k_parse_json(
    const char *json_str,
    Mfc1kData *mfc1k,
    MfcMetadataHeader *header
);

char *mfc1k_serialize_json(
    const Mfc1kData *mfc1k,
    const MfcMetadataHeader *header
);

RfidxStatus mfc1k_parse_nfc(
    const char *nfc_str,
    Mfc1kData *mfc1k,
    MfcMetadataHeader *header
);

char *mfc1k_serialize_nfc(
    const Mfc1kData *mfc1k,
    const MfcMetadataHeader *header
);

RfidxStatus mfc1k_generate(
    Mfc1kData *mfc1k,
    MfcMetadataHeader *header
);

RfidxStatus mfc1k_wipe(Mfc1kData* ntag215);

RFIDX_EXPORT RfidxStatus mfc1k_transform_data(
    Mfc1kData *mfc1k,
    MfcMetadataHeader *header,
    TransformCommand command
);

_Static_assert(sizeof(Mfc1kData) == MFC_1K_TOTAL_BYTES, "Mifare Classic 1K data size mismatch");

#endif //LIBRFIDX_MIFARE_CLASSIC_1K_CORE_H
