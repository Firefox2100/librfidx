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
#include <setjmp.h>
#include <unistd.h>
#include <cJSON.h>
#include <cmocka.h>
#include "librfidx/mifare/mifare_classic_1k.h"

static void assert_manufacturer_correct(const Mfc1kData *mfc1k) {
    const uint8_t expected_uid[4]                   = {0x2A, 0xF9, 0x02, 0x4A};
    const uint8_t expected_manufacturer_data[12]    = {0x88, 0x04, 0x00, 0xC8, 0x48, 0x00,
                                                    0x20, 0x00, 0x00, 0x00, 0x21};
    const uint8_t expected_bcc                      = 0x9B;

    assert_memory_equal(mfc1k->manufacturer_data_4b.nuid, expected_uid, sizeof(expected_uid));
    assert_memory_equal(&mfc1k->manufacturer_data_4b.bcc, &expected_bcc, 1);
    assert_memory_equal(
        mfc1k->manufacturer_data_4b.manufacturer_data,
        expected_manufacturer_data,
        sizeof(expected_manufacturer_data)
        );
}

static void test_mfc1k_load_binary_dump_real(void **state) {
    const char filename[] = "tests/assets/mifare-classic-1k-v2.bin";
    Mfc1kData loaded_data = {0};
    MfcMetadataHeader loaded_header = {0};

    const RfidxStatus status = mfc1k_load_from_binary(filename, &loaded_data, &loaded_header);

    assert_int_equal(status, RFIDX_OK);
    assert_manufacturer_correct(&loaded_data);
}

static void test_mfc1k_save_binary_and_reload(void **state) {
    const char filename[] = "tests/assets/mifare-classic-1k-v2.bin";
    char tmp_filename[] = "/tmp/mfc1k-test-XXXXXX";
    const int fd = mkstemp(tmp_filename);
    assert_true(fd != -1);
    close(fd);

    Mfc1kData loaded_data = {0};
    MfcMetadataHeader loaded_header = {0};

    RfidxStatus status = mfc1k_load_from_binary(filename, &loaded_data, &loaded_header);
    assert_int_equal(status, RFIDX_OK);

    status = mfc1k_save_to_binary(tmp_filename, &loaded_data, &loaded_header);
    assert_int_equal(status, RFIDX_OK);

    status = mfc1k_load_from_binary(tmp_filename, &loaded_data, &loaded_header);
    assert_int_equal(status, RFIDX_OK);
    assert_manufacturer_correct(&loaded_data);

    unlink(tmp_filename);
}

static void test_mfc1k_load_json_dump_real(void **state) {
    const char filename[] = "tests/assets/mifare-classic-1k-v2.json";
    Mfc1kData loaded_data = {0};
    MfcMetadataHeader loaded_header = {0};

    const RfidxStatus status = mfc1k_load_from_json(filename, &loaded_data, &loaded_header);

    assert_int_equal(status, RFIDX_OK);
    assert_manufacturer_correct(&loaded_data);
}

static void test_mfc1k_save_json_dump_and_reload(void **state) {
    const char filename[] = "tests/assets/mifare-classic-1k-v2.json";
    char tmp_filename[] = "/tmp/mfc1k-test-XXXXXX";
    const int fd = mkstemp(tmp_filename);
    assert_true(fd != -1);
    close(fd);

    Mfc1kData loaded_data = {0};
    MfcMetadataHeader loaded_header = {0};

    RfidxStatus status = mfc1k_load_from_json(filename, &loaded_data, &loaded_header);
    assert_int_equal(status, RFIDX_OK);

    status = mfc1k_save_to_json(tmp_filename, &loaded_data, &loaded_header);
    assert_int_equal(status, RFIDX_OK);

    status = mfc1k_load_from_json(tmp_filename, &loaded_data, &loaded_header);
    assert_int_equal(status, RFIDX_OK);
    assert_manufacturer_correct(&loaded_data);

    unlink(tmp_filename);
}

static void test_mfc1k_load_nfc_dump_real(void **state) {
    const char filename[] = "tests/assets/mifare-classic-1k-v2.nfc";
    Mfc1kData loaded_data = {0};
    MfcMetadataHeader loaded_header = {0};

    const RfidxStatus status = mfc1k_load_from_nfc(filename, &loaded_data, &loaded_header);

    assert_int_equal(status, RFIDX_OK);
    assert_manufacturer_correct(&loaded_data);
}

static void test_mfc1k_save_nfc_dump_and_reload(void **state) {
    const char filename[] = "tests/assets/mifare-classic-1k-v2.nfc";
    char tmp_filename[] = "/tmp/mfc1k-test-XXXXXX";
    const int fd = mkstemp(tmp_filename);
    assert_true(fd != -1);
    close(fd);

    Mfc1kData loaded_data = {0};
    MfcMetadataHeader loaded_header = {0};

    RfidxStatus status = mfc1k_load_from_nfc(filename, &loaded_data, &loaded_header);
    assert_int_equal(status, RFIDX_OK);

    status = mfc1k_save_to_nfc(tmp_filename, &loaded_data, &loaded_header);
    assert_int_equal(status, RFIDX_OK);

    status = mfc1k_load_from_nfc(tmp_filename, &loaded_data, &loaded_header);
    assert_int_equal(status, RFIDX_OK);
    assert_manufacturer_correct(&loaded_data);

    unlink(tmp_filename);
}

static const struct CMUnitTest mfc1k_tests[] = {
    cmocka_unit_test(test_mfc1k_load_binary_dump_real),
    cmocka_unit_test(test_mfc1k_save_binary_and_reload),
    cmocka_unit_test(test_mfc1k_load_json_dump_real),
    cmocka_unit_test(test_mfc1k_save_json_dump_and_reload),
    cmocka_unit_test(test_mfc1k_load_nfc_dump_real),
    cmocka_unit_test(test_mfc1k_save_nfc_dump_and_reload),
};

const struct CMUnitTest* get_mfc1k_tests(size_t *count) {
    if (count) *count = sizeof(mfc1k_tests) / sizeof(mfc1k_tests[0]);
    return mfc1k_tests;
}
