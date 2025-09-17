/*
 * librfidx - Universal RFID Tag Format Parser and Converter
 *
 * Copyright (c) 2025. Firefox2100
 *
 * This software is released under the MIT License.
 * SPDX-License-Identifier: MIT
 */

#include <stdio.h>
#include <string.h>
#include <setjmp.h>
#include <cmocka.h>

#include "librfidx/rfidx.h"
#include "librfidx/ntag/ntag215.h"

RfidxStatus save_tag_to_file(
    const void *data,
    const void *header,
    TagType tag_type,
    FileFormat output_format,
    const char *filename,
    FILE *output_stream,
    FILE *error_stream
);
RfidxStatus transform_tag(
    TagType tag_type,
    TransformCommand command,
    void **data,
    void **header,
    const char *uuid,
    const char *retail_key
);
TransformCommand string_to_transform_command(const char *str);

static void test_rfidx_string_to_transform_command(void **state) {
    (void) state;
    assert_int_equal(string_to_transform_command("generate"), TRANSFORM_GENERATE);
    assert_int_equal(string_to_transform_command("randomize-uid"), TRANSFORM_RANDOMIZE_UID);
    assert_int_equal(string_to_transform_command("wipe"), TRANSFORM_WIPE);
    assert_int_equal(string_to_transform_command("unknown"), TRANSFORM_NONE);
    assert_int_equal(string_to_transform_command(NULL), TRANSFORM_NONE);
}

static void test_rfidx_read_tag_from_file_ntag215(void **state) {
    (void) state;
    void *data = NULL;
    void *header = NULL;
    const TagType type = read_tag_from_file("./tests/assets/ntag215.bin", NTAG_215, &data, &header);
    assert_int_equal(type, NTAG_215);
    assert_non_null(data);
    assert_non_null(header);
    // free(data);
    // free(header);
}

static void test_rfidx_read_tag_from_file_amiibo(void **state) {
    (void) state;
    void *data = NULL;
    void *header = NULL;
    const TagType type = read_tag_from_file("./tests/assets/ntag215.bin", AMIIBO, &data, &header);
    assert_int_equal(type, AMIIBO);
    assert_non_null(data);
    assert_non_null(header);
    // free(data);
    // free(header);
}

static void test_rfidx_read_tag_from_file_unknown(void **state) {
    (void) state;
    void *data = (void*)0x1;
    void *header = (void*)0x2;
    const TagType type = read_tag_from_file("./tests/assets/ntag215.bin", TAG_UNSPECIFIED, &data, &header);
    assert_int_equal(type, TAG_UNKNOWN);
    assert_ptr_equal(data, (void*)0x1);
    assert_ptr_equal(header, (void*)0x2);
}

static void test_rfidx_read_tag_from_file_missing(void **state) {
    (void) state;
    void *data = NULL;
    void *header = NULL;
    const TagType type = read_tag_from_file("./tests/assets/missing.bin", NTAG_215, &data, &header);
    assert_int_equal(type, TAG_ERROR);
    // if (data) free(data);
    // if (header) free(header);
}

static void test_rfidx_save_tag_to_file_binary(void **state) {
    (void) state;
    void *data = NULL;
    void *header = NULL;
    const TagType type = read_tag_from_file("./tests/assets/ntag215.bin", NTAG_215, &data, &header);
    assert_int_equal(type, NTAG_215);

    char *out_buf = NULL, *err_buf = NULL;
    size_t out_size = 0, err_size = 0;
    FILE *out_stream = open_memstream(&out_buf, &out_size);
    FILE *err_stream = open_memstream(&err_buf, &err_size);

    const RfidxStatus status = save_tag_to_file(data, header, NTAG_215, FORMAT_BINARY, NULL, out_stream, err_stream);

    fclose(out_stream);
    fclose(err_stream);

    assert_int_equal(status, RFIDX_OK);
    assert_string_equal(err_buf, "");
    assert_true(strncmp(out_buf, "Tag data: \n", 11) == 0);

    // free(out_buf);
    // free(err_buf);
    // free(data);
    // free(header);
}

static void test_rfidx_save_tag_to_file_invalid_format(void **state) {
    (void) state;
    Ntag215Data data = {0};
    Ntag21xMetadataHeader header = {0};

    char *out_buf = NULL, *err_buf = NULL;
    size_t out_size = 0, err_size = 0;
    FILE *out_stream = open_memstream(&out_buf, &out_size);
    FILE *err_stream = open_memstream(&err_buf, &err_size);

    const RfidxStatus status = save_tag_to_file(&data, &header, NTAG_215, FORMAT_EML, "dummy", out_stream, err_stream);

    fclose(out_stream);
    fclose(err_stream);

    assert_int_equal(status, RFIDX_NUMERICAL_OPERATION_FAILED);
    assert_non_null(strstr(err_buf, "Failed to transform"));

    // free(out_buf);
    // free(err_buf);
}

static void test_rfidx_transform_tag_ntag215_wipe(void **state) {
    (void) state;
    Ntag215Data data;
    Ntag21xMetadataHeader header;
    memset(&data, 0xFF, sizeof(data));
    memset(&header, 0xAA, sizeof(header));
    Ntag215Data *pdata = &data;
    Ntag21xMetadataHeader *pheader = &header;
    const RfidxStatus status = transform_tag(NTAG_215, TRANSFORM_WIPE, (void**)&pdata, (void**)&pheader, NULL, NULL);
    assert_int_equal(status, RFIDX_OK);
    for (int i = 0; i < NTAG215_NUM_USER_PAGES; ++i) {
        assert_memory_equal(data.structure.user_memory[i], (uint8_t[NTAG21X_PAGE_SIZE]){0}, NTAG21X_PAGE_SIZE);
    }
}

static void test_rfidx_transform_tag_amiibo_missing_key(void **state) {
    (void) state;
    void *data = NULL;
    void *header = NULL;
    const RfidxStatus status = transform_tag(AMIIBO, TRANSFORM_RANDOMIZE_UID, &data, &header, NULL, NULL);
    assert_int_equal(status, RFIDX_NUMERICAL_OPERATION_FAILED);
}

static void test_rfidx_transform_tag_unknown(void **state) {
    (void) state;
    void *data = NULL;
    void *header = NULL;
    const RfidxStatus status = transform_tag(TAG_UNKNOWN, TRANSFORM_WIPE, &data, &header, NULL, NULL);
    assert_int_equal(status, RFIDX_FILE_FORMAT_ERROR);
}

static void test_rfidx_randomize_uid_ntag215(void **state) {
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
}

static void test_rfidx_randomize_uid_mfc1k(void **state) {
    char *argv[] = {
        "rfidx",
        "--input", "./tests/assets/mifare-classic-1k-v2.bin",
        "--input-type", "mfc1k",
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
}

static void test_rfidx_randomize_uid_amiibo(void **state) {
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
}

static void test_rfidx_generate_amiibo(void **state) {
    char *argv[] = {
        "rfidx",
        "--input-type", "amiibo",
        "--output-format", "binary",
        "--transform", "generate",
        "--uuid", "09d0030102bb0e02",
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
}

static const struct CMUnitTest rfidx_tests[] = {
    cmocka_unit_test(test_rfidx_string_to_transform_command),
    cmocka_unit_test(test_rfidx_read_tag_from_file_ntag215),
    cmocka_unit_test(test_rfidx_read_tag_from_file_amiibo),
    cmocka_unit_test(test_rfidx_read_tag_from_file_unknown),
    cmocka_unit_test(test_rfidx_read_tag_from_file_missing),
    cmocka_unit_test(test_rfidx_save_tag_to_file_binary),
    cmocka_unit_test(test_rfidx_save_tag_to_file_invalid_format),
    cmocka_unit_test(test_rfidx_transform_tag_ntag215_wipe),
    cmocka_unit_test(test_rfidx_transform_tag_amiibo_missing_key),
    cmocka_unit_test(test_rfidx_transform_tag_unknown),
    cmocka_unit_test(test_rfidx_randomize_uid_ntag215),
    cmocka_unit_test(test_rfidx_randomize_uid_mfc1k),
    cmocka_unit_test(test_rfidx_randomize_uid_amiibo),
    cmocka_unit_test(test_rfidx_generate_amiibo),
};

const struct CMUnitTest *get_rfidx_tests(size_t *count) {
    if (count) *count = sizeof(rfidx_tests) / sizeof(rfidx_tests[0]);
    return rfidx_tests;
}
