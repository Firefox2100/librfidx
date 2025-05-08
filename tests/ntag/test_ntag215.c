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
#include <unistd.h>
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

    ck_assert_mem_eq(header->version, expected_version, sizeof(expected_version));
    ck_assert_mem_eq(header->tbo0, expected_tbo0, sizeof(expected_tbo0));
    ck_assert_int_eq(header->tbo1, expected_tbo1);
    ck_assert_int_eq(header->memory_max, expected_memory_max);
    ck_assert_mem_eq(header->signature, expected_signature, sizeof(expected_signature));
    ck_assert_mem_eq(header->counter0, expected_counter0, sizeof(expected_counter0));
    ck_assert_int_eq(header->tearing0, expected_tearing0);
    ck_assert_mem_eq(header->counter1, expected_counter1, sizeof(expected_counter1));
    ck_assert_int_eq(header->tearing1, expected_tearing1);
    ck_assert_mem_eq(header->counter2, expected_counter2, sizeof(expected_counter2));
    ck_assert_int_eq(header->tearing2, expected_tearing2);
}

START_TEST(test_load_binary_dump)
{
    char filename[] = "/tmp/ntagtestXXXXXX";
    const int fd = mkstemp(filename);
    ck_assert_msg(fd != -1, "Failed to create temp file");

    FILE *fp = fdopen(fd, "wb");
    ck_assert_ptr_nonnull(fp);

    Ntag215Data data = {0};
    memset(&data, 0xAA, sizeof(data));
    fwrite(&data, sizeof(data), 1, fp);
    fclose(fp);

    Ntag215Data loaded_data = {0};
    Ntag21xMetadataHeader loaded_header = {0};

    const RfidxStatus status = ntag215_load_from_binary(filename, &loaded_data, &loaded_header);
    ck_assert_int_eq(status, RFIDX_OK);
    ck_assert_mem_eq(&loaded_data, &data, sizeof(data));

    unlink(filename);
}
END_TEST

START_TEST(test_load_binary_dump_with_header)
{
    char filename[] = "/tmp/ntagtestXXXXXX";
    const int fd = mkstemp(filename);
    ck_assert_msg(fd != -1, "Failed to create temp file");

    FILE *fp = fdopen(fd, "wb");
    ck_assert_ptr_nonnull(fp);

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
    ck_assert_int_eq(status, RFIDX_OK);
    ck_assert_mem_eq(&loaded_data, &data, sizeof(data));
    ck_assert_mem_eq(&loaded_header, &header, sizeof(header));

    unlink(filename);
}
END_TEST

START_TEST(test_save_binary_and_reload)
{
    char filename[] = "/tmp/ntagtestXXXXXX";
    const int fd = mkstemp(filename);
    ck_assert_msg(fd != -1, "Failed to create temp file");
    close(fd);  // Save will fopen it again

    Ntag215Data data = {0};
    Ntag21xMetadataHeader header = {0};
    memset(&data, 0xDE, sizeof(data));
    memset(&header, 0xAD, sizeof(header));

    RfidxStatus status = ntag215_save_to_binary(filename, &data, &header);
    ck_assert_int_eq(status, RFIDX_OK);

    Ntag215Data loaded_data = {0};
    Ntag21xMetadataHeader loaded_header = {0};
    status = ntag215_load_from_binary(filename, &loaded_data, &loaded_header);
    ck_assert_int_eq(status, RFIDX_OK);
    ck_assert_mem_eq(&loaded_data, &data, sizeof(data));
    ck_assert_mem_eq(&loaded_header, &header, sizeof(header));

    unlink(filename);
}
END_TEST

START_TEST(test_load_binary_dump_real) {
    const char filename[] = "tests/assets/ntag215.bin";
    Ntag215Data loaded_data = {0};
    Ntag21xMetadataHeader loaded_header = {0};

    const RfidxStatus status = ntag215_load_from_binary(filename, &loaded_data, &loaded_header);

    ck_assert_int_eq(status, RFIDX_OK);

    assert_header_correct(&loaded_header);
}
END_TEST

START_TEST(test_load_json_dump_real) {
    const char filename[] = "tests/assets/ntag215.json";
    Ntag215Data loaded_data = {0};
    Ntag21xMetadataHeader loaded_header = {0};

    const RfidxStatus status = ntag215_load_from_json(filename, &loaded_data, &loaded_header);

    ck_assert_int_eq(status, RFIDX_OK);

    assert_header_correct(&loaded_header);
}
END_TEST

START_TEST(test_save_json_dump_and_reload) {
    const char filename[] = "tests/assets/ntag215.json";
    char tmp_filename[] = "/tmp/ntagtestXXXXXX";
    const int fd = mkstemp(tmp_filename);
    ck_assert_msg(fd != -1, "Failed to create temp file");

    Ntag215Data loaded_data = {0};
    Ntag21xMetadataHeader loaded_header = {0};

    RfidxStatus status = ntag215_load_from_json(filename, &loaded_data, &loaded_header);
    ck_assert_int_eq(status, RFIDX_OK);

    status = ntag215_save_to_json(tmp_filename, &loaded_data, &loaded_header);
    ck_assert_int_eq(status, RFIDX_OK);

    status = ntag215_load_from_json(tmp_filename, &loaded_data, &loaded_header);
    ck_assert_int_eq(status, RFIDX_OK);

    assert_header_correct(&loaded_header);
}
END_TEST

START_TEST(test_load_nfc_dump_real) {
    const char filename[] = "tests/assets/ntag215.nfc";
    Ntag215Data loaded_data = {0};
    Ntag21xMetadataHeader loaded_header = {0};

    const RfidxStatus status = ntag215_load_from_nfc(filename, &loaded_data, &loaded_header);

    ck_assert_int_eq(status, RFIDX_OK);

    assert_header_correct(&loaded_header);
}
END_TEST

START_TEST(test_save_nfc_dump_and_reload) {
    const char filename[] = "tests/assets/ntag215.nfc";
    char tmp_filename[] = "/tmp/ntagtestXXXXXX";
    const int fd = mkstemp(tmp_filename);
    ck_assert_msg(fd != -1, "Failed to create temp file");

    Ntag215Data loaded_data = {0};
    Ntag21xMetadataHeader loaded_header = {0};

    RfidxStatus status = ntag215_load_from_nfc(filename, &loaded_data, &loaded_header);
    ck_assert_int_eq(status, RFIDX_OK);

    status = ntag215_save_to_nfc(tmp_filename, &loaded_data, &loaded_header);
    ck_assert_int_eq(status, RFIDX_OK);

    status = ntag215_load_from_nfc(tmp_filename, &loaded_data, &loaded_header);
    ck_assert_int_eq(status, RFIDX_OK);

    assert_header_correct(&loaded_header);
}

TCase *ntag215_binary_io_case(void) {
    TCase *tc = tcase_create("Ntag215 Binary IO");
    tcase_add_test(tc, test_load_binary_dump);
    tcase_add_test(tc, test_load_binary_dump_with_header);
    tcase_add_test(tc, test_save_binary_and_reload);
    tcase_add_test(tc, test_load_binary_dump_real);

    return tc;
}

TCase *ntag215_json_io_case(void) {
    TCase *tc = tcase_create("Ntag215 JSON IO");
    tcase_add_test(tc, test_load_json_dump_real);
    tcase_add_test(tc, test_save_json_dump_and_reload);

    return tc;
}

TCase *ntag215_nfc_io_case(void) {
    TCase *tc = tcase_create("Ntag215 NFC IO");
    tcase_add_test(tc, test_load_nfc_dump_real);
    tcase_add_test(tc, test_save_nfc_dump_and_reload);

    return tc;
}
