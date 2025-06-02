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
#include <unistd.h>
#include <setjmp.h>
#include <cmocka.h>
#include "librfidx/application/amiibo_core.h"
#include "librfidx/common.h"
#include "librfidx/ntag/ntag215.h"
#include "librfidx/application/amiibo.h"

static void test_amiibo_load_dumped_keys(void **state) {
    const char *filename = "tests/assets/key_retail.bin";
    DumpedKeys keys = {0};
    const RfidxStatus load_status = amiibo_load_dumped_keys(filename, &keys);

    assert_int_equal(load_status, RFIDX_OK);
    assert_int_not_equal(keys.data.magicBytesSize, 0);
    assert_int_equal(keys.data.magicBytesSize, 14);
    assert_string_equal(keys.data.typeString, "unfixed infos");

    const uint8_t expected_data_hmac[16] = {
        0x1D, 0x16, 0x4B, 0x37, 0x5B, 0x72, 0xA5, 0x57,
        0x28, 0xB9, 0x1D, 0x64, 0xB6, 0xA3, 0xC2, 0x05
    };
    assert_memory_equal(keys.data.hmacKey, expected_data_hmac, 16);

    assert_int_not_equal(keys.tag.magicBytesSize, 0);
    assert_int_equal(keys.tag.magicBytesSize, 16);
    assert_string_equal(keys.tag.typeString, "locked secret");

    const uint8_t expected_tag_hmac[16] = {
        0x7F, 0x75, 0x2D, 0x28, 0x73, 0xA2, 0x00, 0x17,
        0xFE, 0xF8, 0x5C, 0x05, 0x75, 0x90, 0x4B, 0x6D
    };
    assert_memory_equal(keys.tag.hmacKey, expected_tag_hmac, 16);
}

static void test_amiibo_save_dumped_keys_and_reload(void **state) {
    char filename[] = "/tmp/amiibotestXXXXXX";
    const int fd = mkstemp(filename);
    assert_true(fd != -1);
    close(fd);

    const char *real_key_name = "tests/assets/key_retail.bin";
    DumpedKeys keys = {0};
    RfidxStatus status = amiibo_load_dumped_keys(real_key_name, &keys);

    assert_int_equal(status, RFIDX_OK);

    status = amiibo_save_dumped_keys(filename, &keys);

    assert_int_equal(status, RFIDX_OK);
    DumpedKeys loaded_keys = {0};
    status = amiibo_load_dumped_keys(filename, &loaded_keys);

    assert_int_equal(status, RFIDX_OK);
    assert_memory_equal(&keys.data, &loaded_keys.data, sizeof(keys.data));
    assert_memory_equal(&keys.tag, &loaded_keys.tag, sizeof(keys.tag));

    unlink(filename);
}

static void test_amiibo_derive_keys(void **state) {
    const char *key_name = "tests/assets/key_retail.bin";
    const char *amiibo_name = "tests/assets/ntag215.bin";

    Ntag215Data loaded_data = {0};
    Ntag21xMetadataHeader loaded_header = {0};
    RfidxStatus status = ntag215_load_from_binary(amiibo_name, &loaded_data, &loaded_header);
    assert_int_equal(status, RFIDX_OK);

    const AmiiboData *amiibo_data = (AmiiboData *) &loaded_data.bytes;

    DumpedKeys keys = {0};
    status = amiibo_load_dumped_keys(key_name, &keys);
    assert_int_equal(status, RFIDX_OK);

    DerivedKey tag_key = {0};
    DerivedKey data_key = {0};
    status = amiibo_derive_key(&keys.tag, amiibo_data, &tag_key);
    assert_int_equal(status, RFIDX_OK);
    status = amiibo_derive_key(&keys.data, amiibo_data, &data_key);
    assert_int_equal(status, RFIDX_OK);
}

static void test_amiibo_cipher(void **state) {
    const char *key_name = "tests/assets/key_retail.bin";
    const char *amiibo_name = "tests/assets/ntag215.bin";

    Ntag215Data loaded_data = {0};
    Ntag21xMetadataHeader loaded_header = {0};
    RfidxStatus status = ntag215_load_from_binary(amiibo_name, &loaded_data, &loaded_header);
    assert_int_equal(status, RFIDX_OK);

    AmiiboData *amiibo_data = (AmiiboData *) &loaded_data.bytes;

    DumpedKeys keys = {0};
    status = amiibo_load_dumped_keys(key_name, &keys);
    assert_int_equal(status, RFIDX_OK);

    DerivedKey tag_key = {0};
    DerivedKey data_key = {0};
    status = amiibo_derive_key(&keys.tag, amiibo_data, &tag_key);
    assert_int_equal(status, RFIDX_OK);
    status = amiibo_derive_key(&keys.data, amiibo_data, &data_key);
    assert_int_equal(status, RFIDX_OK);

    status = amiibo_cipher(&data_key, amiibo_data);
    assert_int_equal(status, RFIDX_OK);
}

static void test_amiibo_validate_signature(void **state) {
    const char *key_name = "tests/assets/key_retail.bin";
    const char *amiibo_name = "tests/assets/ntag215.bin";

    Ntag215Data loaded_data = {0};
    Ntag21xMetadataHeader loaded_header = {0};
    RfidxStatus status = ntag215_load_from_binary(amiibo_name, &loaded_data, &loaded_header);
    assert_int_equal(status, RFIDX_OK);

    AmiiboData *amiibo_data = (AmiiboData *) &loaded_data.bytes;

    DumpedKeys keys = {0};
    status = amiibo_load_dumped_keys(key_name, &keys);
    assert_int_equal(status, RFIDX_OK);

    DerivedKey tag_key = {0};
    DerivedKey data_key = {0};
    status = amiibo_derive_key(&keys.tag, amiibo_data, &tag_key);
    assert_int_equal(status, RFIDX_OK);
    status = amiibo_derive_key(&keys.data, amiibo_data, &data_key);
    assert_int_equal(status, RFIDX_OK);

    status = amiibo_cipher(&data_key, amiibo_data);
    assert_int_equal(status, RFIDX_OK);

    status = amiibo_validate_signature(&tag_key, &data_key, amiibo_data);
    assert_int_equal(status, RFIDX_OK);
}

static void test_amiibo_generate(void **state) {
    const uint8_t uuid [8] = {
        0x09, 0xd0, 0x03, 0x01, 0x02, 0xbb, 0x0e, 0x02,
    };
    AmiiboData amiibo_data = {0};
    Ntag21xMetadataHeader header = {0};

    RfidxStatus status = rfidx_init_rng(NULL, NULL);
    assert_true(rfidx_rng_initialized);
    assert_int_equal(status, 0);

    status = amiibo_generate(uuid, &amiibo_data, &header);
    assert_int_equal(status, RFIDX_OK);
    assert_memory_equal(uuid, amiibo_data.amiibo.model_info.bytes, 8);

    status = rfidx_free_rng();
    assert_false(rfidx_rng_initialized);
    assert_int_equal(status, 0);
}

static void test_amiibo_sign_payload(void **state) {
    const uint8_t uuid [8] = {
        0x09, 0xd0, 0x03, 0x01, 0x02, 0xbb, 0x0e, 0x02,
    };
    AmiiboData amiibo_data = {0};
    Ntag21xMetadataHeader header = {0};

    RfidxStatus status = rfidx_init_rng(NULL, NULL);
    assert_true(rfidx_rng_initialized);
    assert_int_equal(status, 0);

    status = amiibo_generate(uuid, &amiibo_data, &header);
    assert_int_equal(status, RFIDX_OK);
    assert_memory_equal(uuid, amiibo_data.amiibo.model_info.bytes, 8);

    const char *key_name = "tests/assets/key_retail.bin";
    DumpedKeys keys = {0};
    status = amiibo_load_dumped_keys(key_name, &keys);
    assert_int_equal(status, RFIDX_OK);

    DerivedKey tag_key = {0};
    DerivedKey data_key = {0};
    status = amiibo_derive_key(&keys.tag, &amiibo_data, &tag_key);
    assert_int_equal(status, RFIDX_OK);
    status = amiibo_derive_key(&keys.data, &amiibo_data, &data_key);
    assert_int_equal(status, RFIDX_OK);

    status = amiibo_sign_payload(&tag_key, &data_key, &amiibo_data);
    assert_int_equal(status, RFIDX_OK);

    status = amiibo_validate_signature(&tag_key, &data_key, &amiibo_data);
    assert_int_equal(status, RFIDX_OK);

    status = rfidx_free_rng();
    assert_false(rfidx_rng_initialized);
    assert_int_equal(status, 0);
}

static void test_amiibo_wipe(void **state) {
    const char *key_name = "tests/assets/key_retail.bin";
    const char *amiibo_name = "tests/assets/ntag215.bin";

    Ntag215Data loaded_data = {0};
    Ntag21xMetadataHeader loaded_header = {0};
    RfidxStatus status = ntag215_load_from_binary(amiibo_name, &loaded_data, &loaded_header);
    assert_int_equal(status, RFIDX_OK);

    AmiiboData *amiibo_data = (AmiiboData *) &loaded_data.bytes;

    DumpedKeys keys = {0};
    status = amiibo_load_dumped_keys(key_name, &keys);
    assert_int_equal(status, RFIDX_OK);

    DerivedKey tag_key = {0};
    DerivedKey data_key = {0};
    status = amiibo_derive_key(&keys.tag, amiibo_data, &tag_key);
    assert_int_equal(status, RFIDX_OK);
    status = amiibo_derive_key(&keys.data, amiibo_data, &data_key);
    assert_int_equal(status, RFIDX_OK);

    status = amiibo_cipher(&data_key, amiibo_data);
    assert_int_equal(status, RFIDX_OK);

    status = amiibo_wipe(amiibo_data);
    assert_int_equal(status, RFIDX_OK);
}

static const struct CMUnitTest amiibo_tests[] = {
    cmocka_unit_test(test_amiibo_load_dumped_keys),
    cmocka_unit_test(test_amiibo_save_dumped_keys_and_reload),
    cmocka_unit_test(test_amiibo_derive_keys),
    cmocka_unit_test(test_amiibo_cipher),
    cmocka_unit_test(test_amiibo_validate_signature),
    cmocka_unit_test(test_amiibo_generate),
    cmocka_unit_test(test_amiibo_sign_payload),
    cmocka_unit_test(test_amiibo_wipe),
};

const struct CMUnitTest *get_amiibo_tests(size_t *count) {
    if (count) *count = sizeof(amiibo_tests) / sizeof(amiibo_tests[0]);
    return amiibo_tests;
}
