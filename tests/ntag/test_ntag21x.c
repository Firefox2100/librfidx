/*
 * librfidx - Universal RFID Tag Format Parser and Converter
 *
 * Copyright (c) 2025. Firefox2100
 *
 * This software is released under the MIT License.
 * SPDX-License-Identifier: MIT
 */

#include <check.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "librfidx/ntag/ntag21x.h"

START_TEST (test_validate_manufacturer_data)
{
    const char filename[] = "tests/assets/ntag215.bin";
    Ntag21xManufacturerData manufacturer_data = {0};

    FILE *file = fopen(filename, "rb");
    if (!file) {
        ck_abort_msg("Failed to open file");
    }

    if (fseek(file, sizeof(Ntag21xMetadataHeader), SEEK_SET) != 0) {
        fclose(file);
        ck_abort_msg("Failed to skip metadata header");
    }

    if (fread(&manufacturer_data, 1, sizeof(Ntag21xManufacturerData), file) != sizeof(Ntag21xManufacturerData)) {
        fclose(file);
        ck_abort_msg("Failed to read manufacturer data");
    }

    const RfidxStatus status = ntag21x_validate_manufacturer_data(&manufacturer_data);

    ck_assert_int_eq(status, RFIDX_OK);
}
END_TEST

START_TEST (test_randomize_uid)
{
    const char filename[] = "tests/assets/ntag215.bin";
    Ntag21xManufacturerData manufacturer_data = {0};

    FILE *file = fopen(filename, "rb");
    if (!file) {
        ck_abort_msg("Failed to open file");
    }

    if (fseek(file, sizeof(Ntag21xMetadataHeader), SEEK_SET) != 0) {
        fclose(file);
        ck_abort_msg("Failed to skip metadata header");
    }

    if (fread(&manufacturer_data, 1, sizeof(Ntag21xManufacturerData), file) != sizeof(Ntag21xManufacturerData)) {
        fclose(file);
        ck_abort_msg("Failed to read manufacturer data");
    }

    RfidxStatus status = ntag21x_randomize_uid((unsigned)time(NULL), &manufacturer_data);
    ck_assert_int_eq(status, RFIDX_OK);

    status = ntag21x_validate_manufacturer_data(&manufacturer_data);
    ck_assert_int_eq(status, RFIDX_OK);
}
END_TEST

TCase *ntag21x_manufacturer_case(void) {
    TCase *tc = tcase_create("Ntag21X Manufacturer");
    tcase_add_test(tc, test_validate_manufacturer_data);
    tcase_add_test(tc, test_randomize_uid);

    return tc;
}
