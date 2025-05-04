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

START_TEST(test_load_dump_only)
{
    char filename[] = "/tmp/ntagtestXXXXXX";
    int fd = mkstemp(filename);
    ck_assert_msg(fd != -1, "Failed to create temp file");

    FILE *fp = fdopen(fd, "wb");
    ck_assert_ptr_nonnull(fp);

    Ntag215Data data = {0};
    memset(&data, 0xAA, sizeof(data));
    fwrite(&data, sizeof(data), 1, fp);
    fclose(fp);

    Ntag215Data loaded_data = {0};
    Ntag21xProxmarkHeader loaded_header = {0};

    RfidxStatus status = ntag215_load_from_binary(filename, &loaded_data, &loaded_header);
    ck_assert_int_eq(status, RFIDX_OK);
    ck_assert_mem_eq(&loaded_data, &data, sizeof(data));

    unlink(filename);
}
END_TEST

START_TEST(test_load_with_header)
{
    char filename[] = "/tmp/ntagtestXXXXXX";
    int fd = mkstemp(filename);
    ck_assert_msg(fd != -1, "Failed to create temp file");

    FILE *fp = fdopen(fd, "wb");
    ck_assert_ptr_nonnull(fp);

    Ntag215Data data = {0};
    Ntag21xProxmarkHeader header = {0};
    memset(&data, 0xBB, sizeof(data));
    memset(&header, 0xCC, sizeof(header));

    fwrite(&header, sizeof(header), 1, fp);
    fwrite(&data, sizeof(data), 1, fp);
    fclose(fp);

    Ntag215Data loaded_data = {0};
    Ntag21xProxmarkHeader loaded_header = {0};

    RfidxStatus status = ntag215_load_from_binary(filename, &loaded_data, &loaded_header);
    ck_assert_int_eq(status, RFIDX_OK);
    ck_assert_mem_eq(&loaded_data, &data, sizeof(data));
    ck_assert_mem_eq(&loaded_header, &header, sizeof(header));

    unlink(filename);
}
END_TEST

START_TEST(test_save_and_reload)
{
    char filename[] = "/tmp/ntagtestXXXXXX";
    int fd = mkstemp(filename);
    ck_assert_msg(fd != -1, "Failed to create temp file");
    close(fd);  // Save will fopen it again

    Ntag215Data data = {0};
    Ntag21xProxmarkHeader header = {0};
    memset(&data, 0xDE, sizeof(data));
    memset(&header, 0xAD, sizeof(header));

    RfidxStatus status = ntag215_save_to_binary(filename, &data, &header);
    ck_assert_int_eq(status, RFIDX_OK);

    Ntag215Data loaded_data = {0};
    Ntag21xProxmarkHeader loaded_header = {0};
    status = ntag215_load_from_binary(filename, &loaded_data, &loaded_header);
    ck_assert_int_eq(status, RFIDX_OK);
    ck_assert_mem_eq(&loaded_data, &data, sizeof(data));
    ck_assert_mem_eq(&loaded_header, &header, sizeof(header));

    unlink(filename);
}
END_TEST

TCase *ntag215_io_case(void) {
    TCase *tc = tcase_create("Ntag215 IO");
    tcase_add_test(tc, test_load_dump_only);
    tcase_add_test(tc, test_load_with_signature);
    tcase_add_test(tc, test_save_and_reload);

    return tc;
}
