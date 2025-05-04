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

    Ntag215Data loaded_data;
    NtagSignature sig = {0};
    memset(&loaded_data, 0, sizeof(loaded_data));

    RfidxStatus status = ntag215_load_from_binary(filename, &loaded_data, &sig);
    ck_assert_int_eq(status, RFIDX_OK);
    ck_assert_mem_eq(&loaded_data, &data, sizeof(data));

    unlink(filename);
}
END_TEST

START_TEST(test_load_with_signature)
{
    // Create a temp file with Ntag215Data + NtagSignature
    char filename[] = "/tmp/ntagtestXXXXXX";
    int fd = mkstemp(filename);
    ck_assert_msg(fd != -1, "Failed to create temp file");

    FILE *fp = fdopen(fd, "wb");
    ck_assert_ptr_nonnull(fp);

    Ntag215Data data = {0};
    NtagSignature sig = {0};
    memset(&data, 0xBB, sizeof(data));
    memset(&sig, 0xCC, sizeof(sig));

    fwrite(&data, sizeof(data), 1, fp);
    fwrite(&sig, sizeof(sig), 1, fp);
    fclose(fp);

    Ntag215Data loaded_data;
    NtagSignature loaded_sig;
    memset(&loaded_data, 0, sizeof(loaded_data));
    memset(&loaded_sig, 0, sizeof(loaded_sig));

    RfidxStatus status = ntag215_load_from_binary(filename, &loaded_data, &loaded_sig);
    ck_assert_int_eq(status, RFIDX_OK);
    ck_assert_mem_eq(&loaded_data, &data, sizeof(data));
    ck_assert_mem_eq(&loaded_sig, &sig, sizeof(sig));

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
    NtagSignature sig = {0};
    memset(&data, 0xDE, sizeof(data));
    memset(&sig, 0xAD, sizeof(sig));

    RfidxStatus status = ntag215_save_to_binary(filename, &data, &sig);
    ck_assert_int_eq(status, RFIDX_OK);

    Ntag215Data loaded_data;
    NtagSignature loaded_sig;
    status = ntag215_load_from_binary(filename, &loaded_data, &loaded_sig);
    ck_assert_int_eq(status, RFIDX_OK);
    ck_assert_mem_eq(&loaded_data, &data, sizeof(data));
    ck_assert_mem_eq(&loaded_sig, &sig, sizeof(sig));

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
