/*
 * librfidx - Universal RFID Tag Format Parser and Converter
 *
 * Copyright (c) 2025. Firefox2100
 *
 * This software is released under the MIT License.
 * SPDX-License-Identifier: MIT
 */

#include <stdlib.h>
#include "librfidx/ntag/ntag21x.h"

RfidxStatus ntag21x_validate_manufacturer_data(const Ntag21xManufacturerData *manufacturer_data) {
    if (manufacturer_data->uid0[0] != 0x04) {
        return RFIDX_NTAG21X_UID_ERROR;
    }

    const uint8_t computed_bcc0 = manufacturer_data->uid0[0] ^
                                  manufacturer_data->uid0[1] ^
                                  manufacturer_data->uid0[2] ^ 0x88;
    const uint8_t computed_bcc1 = manufacturer_data->uid1[0] ^
                                  manufacturer_data->uid1[1] ^
                                  manufacturer_data->uid1[2] ^
                                  manufacturer_data->uid1[3];

    if (manufacturer_data->bcc0 != computed_bcc0) {
        return RFIDX_NTAG21X_UID_ERROR;
    }
    if (manufacturer_data->bcc1 != computed_bcc1) {
        return RFIDX_NTAG21X_UID_ERROR;
    }
    if (manufacturer_data->internal != 0x48) {
        // The internal byte is always 0x48 unless on unofficial chips
        // Some systems validate it
        return RFIDX_NTAG21X_FIXED_BYTES_ERROR;
    }

    return RFIDX_OK;
}

RfidxStatus ntag21x_randomize_uid(Ntag21xManufacturerData *manufacturer_data) {
    manufacturer_data->uid0[0] = 0x04;

    if (!rfidx_rng_initialized) {
        return RFIDX_DRNG_ERROR;
    }

    uint8_t buffer[6];
    const int ret = mbedtls_ctr_drbg_random(&rfidx_ctr_drbg, buffer, sizeof(buffer));
    if (ret != 0) {
        return RFIDX_DRNG_ERROR;
    }

    manufacturer_data->uid0[1] = buffer[0];
    manufacturer_data->uid0[2] = buffer[1];

    for (int i = 0; i < 4; i++) {
        manufacturer_data->uid1[i] = buffer[i + 2];
    }

    manufacturer_data->bcc0 = manufacturer_data->uid0[0] ^
                              manufacturer_data->uid0[1] ^
                              manufacturer_data->uid0[2] ^ 0x88;
    manufacturer_data->bcc1 = manufacturer_data->uid1[0] ^
                              manufacturer_data->uid1[1] ^
                              manufacturer_data->uid1[2] ^
                              manufacturer_data->uid1[3];

    return RFIDX_OK;
}
