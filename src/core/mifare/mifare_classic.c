/*
 * librfidx - Universal RFID Tag Format Parser and Converter
 *
 * Copyright (c) 2025. Firefox2100
 *
 * This software is released under the MIT License.
 * SPDX-License-Identifier: MIT
 */

#include "librfidx/mifare/mifare_classic.h"

#include <string.h>

MfcAccessBits mfc_get_access_bits_for_block(const MfcSectorTrailer *trailer, const uint8_t block) {
    MfcAccessBits ab = {0};

    if (block > 3) {
        return ab;
    }

    ab.c1 = (trailer->access_bits[1] >> block) & 0x01;
    ab.c2 = (trailer->access_bits[2] >> block) & 0x01;
    ab.c3 = (trailer->access_bits[2] >> (4 + block)) & 0x01;

    return ab;
}

RfidxStatus mfc_set_access_bits_for_block(MfcSectorTrailer *trailer, const uint8_t block,
                                          const MfcAccessBits access_bits) {
    if (block > 3) return RFIDX_MFC_ACCESS_BITS_ERROR;

    trailer->access_bits[1] &= ~(1 << block);
    trailer->access_bits[1] |= (access_bits.c1 & 0x01) << block;

    trailer->access_bits[2] &= ~(1 << block);
    trailer->access_bits[2] |= (access_bits.c2 & 0x01) << block;

    trailer->access_bits[2] &= ~(1 << (4 + block));
    trailer->access_bits[2] |= (access_bits.c3 & 0x01) << (4 + block);

    const uint8_t c1_inv = (~access_bits.c1) & 0x01;
    const uint8_t c2_inv = (~access_bits.c2) & 0x01;
    const uint8_t c3_inv = (~access_bits.c3) & 0x01;

    trailer->access_bits[0] &= ~(1 << (4 + block));
    trailer->access_bits[0] |= c2_inv << (4 + block);

    trailer->access_bits[0] &= ~(1 << block);
    trailer->access_bits[0] |= c1_inv << block;

    trailer->access_bits[1] &= ~(1 << (4 + block));
    trailer->access_bits[1] |= c3_inv << (4 + block);

    return RFIDX_OK;
}

RfidxStatus mfc_validate_access_bits(const MfcAccessBits *access_bits) {
    if (!access_bits) return RFIDX_MFC_ACCESS_BITS_ERROR;

    if ((access_bits->c1 & ~0x01) || (access_bits->c2 & ~0x01) || (access_bits->c3 & ~0x01)) {
        return RFIDX_MFC_ACCESS_BITS_ERROR;
    }

    return RFIDX_OK;
}

RfidxStatus mfc_validate_manufacturer_data(const uint8_t *manufacturer_data) {
    // There is no validation for Mifare Classic manufacturer data
    return RFIDX_OK;
}

RfidxStatus mfc_randomize_uid(uint8_t *manufacturer_data) {
    if (!rfidx_rng_initialized) {
        return RFIDX_DRNG_ERROR;
    }

    // Check if it's a 4-byte NUID or 7-byte UID
    const uint8_t bcc = manufacturer_data[0] ^ manufacturer_data[1] ^ manufacturer_data[2] ^ manufacturer_data[3];
    if (bcc == manufacturer_data[4]) {
        // 4-byte NUID
        uint8_t buffer[4];
        const int ret = mbedtls_ctr_drbg_random(&rfidx_ctr_drbg, buffer, sizeof(buffer));
        if (ret != 0) {
            return RFIDX_DRNG_ERROR;
        }
        memcpy(manufacturer_data, buffer, sizeof(buffer));
    } else {
        // 7-byte UID
        uint8_t buffer[7];
        const int ret = mbedtls_ctr_drbg_random(&rfidx_ctr_drbg, buffer, sizeof(buffer));
        if (ret != 0) {
            return RFIDX_DRNG_ERROR;
        }
        memcpy(manufacturer_data, buffer, sizeof(buffer));
    }

    return RFIDX_OK;
}
