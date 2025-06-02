/*
 * librfidx - Universal RFID Tag Format Parser and Converter
 *
 * Copyright (c) 2025. Firefox2100
 *
 * This software is released under the MIT License.
 * SPDX-License-Identifier: MIT
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <setjmp.h>
#include <cmocka.h>
#include "librfidx/ntag/ntag21x.h"

static void test_ntag21x_validate_manufacturer_data(void **state) {
    const char filename[] = "tests/assets/ntag215.bin";
    Ntag21xManufacturerData manufacturer_data = {0};

    FILE *file = fopen(filename, "rb");
    assert_non_null(file);

    assert_int_equal(fseek(file, sizeof(Ntag21xMetadataHeader), SEEK_SET), 0);
    assert_int_equal(fread(&manufacturer_data, 1, sizeof(Ntag21xManufacturerData), file),
                     sizeof(Ntag21xManufacturerData));

    const RfidxStatus status = ntag21x_validate_manufacturer_data(&manufacturer_data);

    assert_int_equal(status, RFIDX_OK);

    fclose(file);
}

static void test_ntag21x_validate_manufacturer_data_failed(void **state) {
    Ntag21xManufacturerData correct_data = {
        .uid0 = {0x04, 0x48, 0xB8},
        .bcc0 = 0x7C,
        .uid1 = {0x26, 0x28, 0x79, 0xBF},
        .bcc1 = 0xC8,
        .internal = 0x48,
        .lock = {0x0F, 0xE0}
    };

    Ntag21xManufacturerData *invalid_data = malloc(sizeof(Ntag21xManufacturerData));
    assert_non_null(invalid_data);

    memcpy(invalid_data, &correct_data, sizeof(Ntag21xManufacturerData));
    invalid_data->uid0[0] = 0x05; // Invalid UID first byte
    RfidxStatus status = ntag21x_validate_manufacturer_data(invalid_data);
    assert_int_equal(status, RFIDX_NTAG21X_UID_ERROR);

    memcpy(invalid_data, &correct_data, sizeof(Ntag21xManufacturerData));
    invalid_data->bcc0 = 0xFF; // Invalid BCC0
    status = ntag21x_validate_manufacturer_data(invalid_data);
    assert_int_equal(status, RFIDX_NTAG21X_UID_ERROR);

    memcpy(invalid_data, &correct_data, sizeof(Ntag21xManufacturerData));
    invalid_data->bcc1 = 0xFF; // Invalid BCC1
    status = ntag21x_validate_manufacturer_data(invalid_data);
    assert_int_equal(status, RFIDX_NTAG21X_UID_ERROR);

    memcpy(invalid_data, &correct_data, sizeof(Ntag21xManufacturerData));
    invalid_data->internal = 0x00; // Invalid internal byte
    status = ntag21x_validate_manufacturer_data(invalid_data);
    assert_int_equal(status, RFIDX_NTAG21X_FIXED_BYTES_ERROR);

    free(invalid_data);
}

static void test_ntag21x_randomize_uid(void **state) {
    const char filename[] = "tests/assets/ntag215.bin";
    Ntag21xManufacturerData manufacturer_data = {0};

    FILE *file = fopen(filename, "rb");
    assert_non_null(file);

    assert_int_equal(fseek(file, sizeof(Ntag21xMetadataHeader), SEEK_SET), 0);
    assert_int_equal(fread(&manufacturer_data, 1, sizeof(Ntag21xManufacturerData), file),
                     sizeof(Ntag21xManufacturerData));

    RfidxStatus status = rfidx_init_rng(NULL, NULL);
    assert_true(rfidx_rng_initialized);
    assert_int_equal(status, 0);

    status = ntag21x_randomize_uid(&manufacturer_data);
    assert_int_equal(status, RFIDX_OK);

    status = ntag21x_validate_manufacturer_data(&manufacturer_data);
    assert_int_equal(status, RFIDX_OK);

    status = rfidx_free_rng();
    assert_true(!rfidx_rng_initialized);
    assert_int_equal(status, RFIDX_OK);

    fclose(file);
}

static void test_ntag21x_randomize_uid_failed(void **state) {
    const char filename[] = "tests/assets/ntag215.bin";
    Ntag21xManufacturerData manufacturer_data = {0};

    FILE *file = fopen(filename, "rb");
    assert_non_null(file);

    assert_int_equal(fseek(file, sizeof(Ntag21xMetadataHeader), SEEK_SET), 0);
    assert_int_equal(fread(&manufacturer_data, 1, sizeof(Ntag21xManufacturerData), file),
                     sizeof(Ntag21xManufacturerData));

    RfidxStatus status = ntag21x_randomize_uid(&manufacturer_data);
    assert_int_equal(status, RFIDX_DRNG_ERROR);

    fclose(file);
}

static const struct CMUnitTest ntag21x_tests[] = {
    cmocka_unit_test(test_ntag21x_validate_manufacturer_data),
    cmocka_unit_test(test_ntag21x_validate_manufacturer_data_failed),
    cmocka_unit_test(test_ntag21x_randomize_uid),
    cmocka_unit_test(test_ntag21x_randomize_uid_failed),
};

const struct CMUnitTest *get_ntag21x_tests(size_t *count) {
    if (count) *count = sizeof(ntag21x_tests) / sizeof(ntag21x_tests[0]);
    return ntag21x_tests;
}
