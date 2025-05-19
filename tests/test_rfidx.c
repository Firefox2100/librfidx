/*
 * librfidx - Universal RFID Tag Format Parser and Converter
 *
 * Copyright (c) 2025. Firefox2100
 *
 * This software is released under the MIT License.
 * SPDX-License-Identifier: MIT
 */

#include <check.h>
#include <stdlib.h>

#include "librfidx/rfidx.h"

START_TEST (test_randomize_uid_ntag215)
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
    ck_assert_msg(status == RFIDX_OK, "rfidx_main failed with status: %d: %s", status, err_buf);
    ck_assert_msg(err_buf[0] == '\0', "Error stream should be empty, but got: %s", err_buf);

    ck_assert_msg(
        strncmp(out_buf, "Tag data: \n", 11) == 0,
        "Output does not start with 'Tag data: ': got: %.20s",
        out_buf
    );
    ck_assert_msg(
        strncmp(out_buf + 123, "0448B87C262879BF", 16) != 0,
        "UID should be randomized"
    );

    free(out_buf);
    free(err_buf);
}
END_TEST

START_TEST (test_randomize_uid_amiibo)
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
    ck_assert_msg(status == RFIDX_OK, "rfidx_main failed with status: %d: %s", status, err_buf);
    ck_assert_msg(err_buf[0] == '\0', "Error stream should be empty, but got: %s", err_buf);

    ck_assert_msg(
        strncmp(out_buf, "Tag data: \n", 11) == 0,
        "Output does not start with 'Tag data: ': got: %.20s",
        out_buf
    );
    ck_assert_msg(
        strncmp(out_buf + 123, "0448B87C262879BF", 16) != 0,
        "UID should be randomized"
    );

    free(out_buf);
    free(err_buf);
}
END_TEST

TCase *rfidx_randomize_uid_case(void) {
    TCase *tc = tcase_create("rfidx randomize UID");
    tcase_add_test(tc, test_randomize_uid_ntag215);
    tcase_add_test(tc, test_randomize_uid_amiibo);

    return tc;
}

Suite *rfidx_suite(void) {
    Suite *s = suite_create("rfidx CLI functions");

    suite_add_tcase(s, rfidx_randomize_uid_case());

    return s;
}
