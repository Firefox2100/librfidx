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
#include <string.h>
#include <unistd.h>
#include <cmocka.h>
#include "librfidx/ntag/ntag215.h"

static void assert_header_correct(const Ntag21xMetadataHeader *header) {
    const uint8_t expected_version[8]       = {0x00, 0x04, 0x04, 0x02, 0x01, 0x00, 0x11, 0x03};
    const uint8_t expected_tbo0[2]          = {0x00, 0x00};
    const uint8_t expected_tbo1             = 0x00;
    const uint8_t expected_memory_max       = 0x86;
    const uint8_t expected_signature[32]    = {0};
    const uint8_t expected_counter0[3]      = {0x00, 0x00, 0x00};
    const uint8_t expected_tearing0         = 0x00;
    const uint8_t expected_counter1[3]      = {0x00, 0x00, 0x00};
    const uint8_t expected_tearing1         = 0x00;
    const uint8_t expected_counter2[3]      = {0x00, 0x00, 0x00};
    const uint8_t expected_tearing2         = 0x00;

    assert_memory_equal(header->version, expected_version, sizeof(expected_version));
    assert_memory_equal(header->tbo0, expected_tbo0, sizeof(expected_tbo0));
    assert_int_equal(header->tbo1, expected_tbo1);
    assert_int_equal(header->memory_max, expected_memory_max);
    assert_memory_equal(header->signature, expected_signature, sizeof(expected_signature));
    assert_memory_equal(header->counter0, expected_counter0, sizeof(expected_counter0));
    assert_int_equal(header->tearing0, expected_tearing0);
    assert_memory_equal(header->counter1, expected_counter1, sizeof(expected_counter1));
    assert_int_equal(header->tearing1, expected_tearing1);
    assert_memory_equal(header->counter2, expected_counter2, sizeof(expected_counter2));
    assert_int_equal(header->tearing2, expected_tearing2);
}

static void test_ntag215_load_binary_dump(void **state) {
    char filename[] = "/tmp/ntagtestXXXXXX";
    const int fd = mkstemp(filename);
    assert_true(fd != -1);

    FILE *fp = fdopen(fd, "wb");
    assert_non_null(fp);

    Ntag215Data data = {0};
    memset(&data, 0xAA, sizeof(data));
    fwrite(&data, sizeof(data), 1, fp);
    fclose(fp);

    Ntag215Data loaded_data = {0};
    Ntag21xMetadataHeader loaded_header = {0};

    const RfidxStatus status = ntag215_load_from_binary(filename, &loaded_data, &loaded_header);
    assert_int_equal(status, RFIDX_OK);
    assert_memory_equal(&loaded_data, &data, sizeof(data));

    unlink(filename);
}

static void test_ntag215_load_binary_dump_with_header(void **state) {
    char filename[] = "/tmp/ntagtestXXXXXX";
    const int fd = mkstemp(filename);
    assert_true(fd != -1);

    FILE *fp = fdopen(fd, "wb");
    assert_non_null(fp);

    Ntag215Data data = {0};
    Ntag21xMetadataHeader header = {0};
    memset(&data, 0xBB, sizeof(data));
    memset(&header, 0xCC, sizeof(header));

    fwrite(&header, sizeof(header), 1, fp);
    fwrite(&data, sizeof(data), 1, fp);
    fclose(fp);

    Ntag215Data loaded_data = {0};
    Ntag21xMetadataHeader loaded_header = {0};

    const RfidxStatus status = ntag215_load_from_binary(filename, &loaded_data, &loaded_header);
    assert_int_equal(status, RFIDX_OK);
    assert_memory_equal(&loaded_data, &data, sizeof(data));
    assert_memory_equal(&loaded_header, &header, sizeof(header));

    unlink(filename);
}

static void test_ntag215_save_binary_and_reload(void **state) {
    char filename[] = "/tmp/ntagtestXXXXXX";
    const int fd = mkstemp(filename);
    assert_true(fd != -1);
    close(fd);

    Ntag215Data data = {0};
    Ntag21xMetadataHeader header = {0};
    memset(&data, 0xDE, sizeof(data));
    memset(&header, 0xAD, sizeof(header));

    RfidxStatus status = ntag215_save_to_binary(filename, &data, &header);
    assert_int_equal(status, RFIDX_OK);

    Ntag215Data loaded_data = {0};
    Ntag21xMetadataHeader loaded_header = {0};
    status = ntag215_load_from_binary(filename, &loaded_data, &loaded_header);
    assert_int_equal(status, RFIDX_OK);
    assert_memory_equal(&loaded_data, &data, sizeof(data));
    assert_memory_equal(&loaded_header, &header, sizeof(header));

    unlink(filename);
}

static void test_ntag215_load_binary_dump_real(void **state) {
    const char filename[] = "tests/assets/ntag215.bin";
    Ntag215Data loaded_data = {0};
    Ntag21xMetadataHeader loaded_header = {0};

    const RfidxStatus status = ntag215_load_from_binary(filename, &loaded_data, &loaded_header);

    assert_int_equal(status, RFIDX_OK);

    assert_header_correct(&loaded_header);
}

static void test_ntag215_load_json_dump_real(void **state) {
    const char filename[] = "tests/assets/ntag215.json";
    Ntag215Data loaded_data = {0};
    Ntag21xMetadataHeader loaded_header = {0};

    const RfidxStatus status = ntag215_load_from_json(filename, &loaded_data, &loaded_header);

    assert_int_equal(status, RFIDX_OK);

    assert_header_correct(&loaded_header);
}

static void test_ntag215_save_json_dump_and_reload(void **state) {
    const char filename[] = "tests/assets/ntag215.json";
    char tmp_filename[] = "/tmp/ntagtestXXXXXX";
    const int fd = mkstemp(tmp_filename);
    assert_true(fd != -1);  // Ensure the file descriptor is valid

    Ntag215Data loaded_data = {0};
    Ntag21xMetadataHeader loaded_header = {0};

    RfidxStatus status = ntag215_load_from_json(filename, &loaded_data, &loaded_header);
    assert_int_equal(status, RFIDX_OK);

    status = ntag215_save_to_json(tmp_filename, &loaded_data, &loaded_header);
    assert_int_equal(status, RFIDX_OK);

    status = ntag215_load_from_json(tmp_filename, &loaded_data, &loaded_header);
    assert_int_equal(status, RFIDX_OK);

    assert_header_correct(&loaded_header);
}

static void test_ntag215_load_nfc_dump_real(void **state) {
    const char filename[] = "tests/assets/ntag215.nfc";
    Ntag215Data loaded_data = {0};
    Ntag21xMetadataHeader loaded_header = {0};

    const RfidxStatus status = ntag215_load_from_nfc(filename, &loaded_data, &loaded_header);

    assert_int_equal(status, RFIDX_OK);

    assert_header_correct(&loaded_header);
}

static void test_ntag215_save_nfc_dump_and_reload(void **state) {
    const char filename[] = "tests/assets/ntag215.nfc";
    char tmp_filename[] = "/tmp/ntagtestXXXXXX";
    const int fd = mkstemp(tmp_filename);
    assert_true(fd != -1);  // Ensure the file descriptor is valid

    Ntag215Data loaded_data = {0};
    Ntag21xMetadataHeader loaded_header = {0};

    RfidxStatus status = ntag215_load_from_nfc(filename, &loaded_data, &loaded_header);
    assert_int_equal(status, RFIDX_OK);

    status = ntag215_save_to_nfc(tmp_filename, &loaded_data, &loaded_header);
    assert_int_equal(status, RFIDX_OK);

    status = ntag215_load_from_nfc(tmp_filename, &loaded_data, &loaded_header);
    assert_int_equal(status, RFIDX_OK);

    assert_header_correct(&loaded_header);
}

static const struct CMUnitTest ntag215_tests[] = {
    cmocka_unit_test(test_ntag215_load_binary_dump),
    cmocka_unit_test(test_ntag215_load_binary_dump_with_header),
    cmocka_unit_test(test_ntag215_save_binary_and_reload),
    cmocka_unit_test(test_ntag215_load_binary_dump_real),
    cmocka_unit_test(test_ntag215_load_json_dump_real),
    cmocka_unit_test(test_ntag215_save_json_dump_and_reload),
    cmocka_unit_test(test_ntag215_load_nfc_dump_real),
    cmocka_unit_test(test_ntag215_save_nfc_dump_and_reload),
};

const struct CMUnitTest* get_ntag215_tests(size_t *count) {
    if (count) *count = sizeof(ntag215_tests) / sizeof(ntag215_tests[0]);
    return ntag215_tests;
}
