/*
 * librfidx - Universal RFID Tag Format Parser and Converter
 *
 * Copyright (c) 2025. Firefox2100
 *
 * This software is released under the MIT License.
 * SPDX-License-Identifier: MIT
 */

#ifndef LIBRFIDX_MIFARE_CLASSIC_1K_H
#define LIBRFIDX_MIFARE_CLASSIC_1K_H

#include "librfidx/mifare/mifare_classic_1k_core.h"

#ifndef LIBRFIDX_NO_PLATFORM

RFIDX_EXPORT RfidxStatus mfc1k_load_from_binary(
    const char *filename,
    Mfc1kData *mfc1k,
    MfcMetadataHeader *header
);

RFIDX_EXPORT RfidxStatus mfc1k_save_to_binary(
    const char *filename,
    const Mfc1kData *mfc1k,
    const MfcMetadataHeader *header
);

RFIDX_EXPORT RfidxStatus mfc1k_load_from_json(
    const char *filename,
    Mfc1kData *mfc1k,
    MfcMetadataHeader *header
);

RFIDX_EXPORT RfidxStatus mfc1k_save_to_json(
    const char *filename,
    const Mfc1kData *mfc1k,
    const MfcMetadataHeader *header
);

RFIDX_EXPORT RfidxStatus mfc1k_load_from_nfc(
    const char *filename,
    Mfc1kData *mfc1k,
    MfcMetadataHeader *header
);

RFIDX_EXPORT RfidxStatus mfc1k_save_to_nfc(
    const char *filename,
    const Mfc1kData *mfc1k,
    const MfcMetadataHeader *header
);

#endif

#endif //LIBRFIDX_MIFARE_CLASSIC_1K_H
