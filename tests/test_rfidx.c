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
#include <setjmp.h>
#include <cmocka.h>
#include "librfidx/rfidx.h"

static void test_rfidx_randomize_uid_ntag215(void **state)
{
    char *argv[] = {
        "rfidx",
        "--input", "./tests/assets/ntag215.bin",
        "--input-type", "ntag215",
        "--output-format", "binary",
        "--transform", "randomize-uid",
        NULL
    };
    const int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    char *out_buf = NULL, *err_buf = NULL;
    size_t out_size = 0, err_size = 0;
    FILE *out_stream = open_memstream(&out_buf, &out_size);
    FILE *err_stream = open_memstream(&err_buf, &err_size);

    const RfidxStatus status = rfidx_main(argc, argv, out_stream, err_stream);

    fclose(out_stream);
    fclose(err_stream);
    
    assert_int_equal(status, RFIDX_OK);
    assert_string_equal(err_buf, "");

    assert_true(strncmp(out_buf, "Tag data: \n", 11) == 0);
    assert_true(strncmp(out_buf + 123, "0448B87C262879BF", 16) != 0);

    free(out_buf);
    free(err_buf);
}

static void test_rfidx_randomize_uid_amiibo(void **state)
{
    char *argv[] = {
        "rfidx",
        "--input", "./tests/assets/ntag215.bin",
        "--input-type", "amiibo",
        "--output-format", "binary",
        "--transform", "randomize-uid",
        "--retail-key", "./tests/assets/key_retail.bin",
        NULL
    };
    const int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    char *out_buf = NULL, *err_buf = NULL;
    size_t out_size = 0, err_size = 0;
    FILE *out_stream = open_memstream(&out_buf, &out_size);
    FILE *err_stream = open_memstream(&err_buf, &err_size);

    const RfidxStatus status = rfidx_main(argc, argv, out_stream, err_stream);

    fclose(out_stream);
    fclose(err_stream);
    
    assert_int_equal(status, RFIDX_OK);
    assert_string_equal(err_buf, "");

    assert_true(strncmp(out_buf, "Tag data: \n", 11) == 0);
    assert_true(strncmp(out_buf + 123, "0448B87C262879BF", 16) != 0);

    free(out_buf);
    free(err_buf);
}

static const struct CMUnitTest rfidx_tests[] = {
    cmocka_unit_test(test_rfidx_randomize_uid_ntag215),
    cmocka_unit_test(test_rfidx_randomize_uid_amiibo)
};

const struct CMUnitTest* get_rfidx_tests(size_t *count) {
    if (count) *count = sizeof(rfidx_tests) / sizeof(rfidx_tests[0]);
    return rfidx_tests;
}
