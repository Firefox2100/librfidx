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

    return RFIDX_OK;
}

RfidxStatus ntag21x_randomize_uid(
    const unsigned int r_seed,
    Ntag21xManufacturerData *manufacturer_data
) {
    srand(r_seed);

    manufacturer_data->uid0[0] = 0x04;

    for (int i = 1; i < 3; i++) {
        manufacturer_data->uid0[i] = rand() % 256;
    }
    for (int i = 0; i < 4; i++) {
        manufacturer_data->uid1[i] = rand() % 256;
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
