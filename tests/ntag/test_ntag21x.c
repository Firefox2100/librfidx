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
    assert_non_null(file); // Ensure the file was opened successfully

    assert_int_equal(fseek(file, sizeof(Ntag21xMetadataHeader), SEEK_SET), 0);
    assert_int_equal(fread(&manufacturer_data, 1, sizeof(Ntag21xManufacturerData), file),
                     sizeof(Ntag21xManufacturerData));

    const RfidxStatus status = ntag21x_validate_manufacturer_data(&manufacturer_data);

    assert_int_equal(status, RFIDX_OK);

    fclose(file); // Ensure the file is closed
}

static void test_ntag21x_randomize_uid(void **state) {
    const char filename[] = "tests/assets/ntag215.bin";
    Ntag21xManufacturerData manufacturer_data = {0};

    FILE *file = fopen(filename, "rb");
    assert_non_null(file); // Ensure the file was opened successfully

    assert_int_equal(fseek(file, sizeof(Ntag21xMetadataHeader), SEEK_SET), 0);
    assert_int_equal(fread(&manufacturer_data, 1, sizeof(Ntag21xManufacturerData), file),
                     sizeof(Ntag21xManufacturerData));

    RfidxStatus status = rfidx_init_rng(NULL, NULL);
    assert_true(rfidx_rng_initialized); // Check if RNG was initialized
    assert_int_equal(status, 0);

    status = ntag21x_randomize_uid(&manufacturer_data);
    assert_int_equal(status, RFIDX_OK);

    status = ntag21x_validate_manufacturer_data(&manufacturer_data);
    assert_int_equal(status, RFIDX_OK);

    fclose(file); // Ensure the file is closed
}

static const struct CMUnitTest ntag21x_tests[] = {
    cmocka_unit_test(test_ntag21x_validate_manufacturer_data),
    cmocka_unit_test(test_ntag21x_randomize_uid),
};

const struct CMUnitTest *get_ntag21x_tests(size_t *count) {
    if (count) *count = sizeof(ntag21x_tests) / sizeof(ntag21x_tests[0]);
    return ntag21x_tests;
}
