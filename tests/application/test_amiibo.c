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
#include "librfidx/application/amiibo.h"

START_TEST (test_load_dumped_keys)
{
    const char *filename = "tests/assets/key_retail.bin";
    DumpedKeys keys = {0};
    const RfidxStatus load_status = amiibo_load_dumped_keys(filename, &keys);

    ck_assert_int_eq(load_status, RFIDX_OK);
    ck_assert_int_ne(keys.data.magicBytesSize, 0);
    ck_assert_int_eq(keys.data.magicBytesSize, 14);
    ck_assert_str_eq(keys.data.typeString, "unfixed infos");

    const uint8_t expected_data_hmac[16] = {
        0x1D, 0x16, 0x4B, 0x37, 0x5B, 0x72, 0xA5, 0x57,
        0x28, 0xB9, 0x1D, 0x64, 0xB6, 0xA3, 0xC2, 0x05
    };
    ck_assert_mem_eq(keys.data.hmacKey, expected_data_hmac, 16);

    ck_assert_int_ne(keys.tag.magicBytesSize, 0);
    ck_assert_int_eq(keys.tag.magicBytesSize, 16);
    ck_assert_str_eq(keys.tag.typeString, "locked secret");

    const uint8_t expected_tag_hmac[16] = {
        0x7F, 0x75, 0x2D, 0x28, 0x73, 0xA2, 0x00, 0x17,
        0xFE, 0xF8, 0x5C, 0x05, 0x75, 0x90, 0x4B, 0x6D
    };
    ck_assert_mem_eq(keys.tag.hmacKey, expected_tag_hmac, 16);
}
END_TEST

START_TEST (test_derive_keys)
{
    const char *key_name = "tests/assets/key_retail.bin";
    const char *amiibo_name = "tests/assets/ntag215.bin";

    Ntag215Data loaded_data = {0};
    Ntag21xMetadataHeader loaded_header = {0};
    RfidxStatus status = ntag215_load_from_binary(amiibo_name, &loaded_data, &loaded_header);
    ck_assert_int_eq(status, RFIDX_OK);

    const AmiiboData *amiibo_data = (AmiiboData *) &loaded_data.bytes;

    DumpedKeys keys = {0};
    status = amiibo_load_dumped_keys(key_name, &keys);
    ck_assert_int_eq(status, RFIDX_OK);

    DerivedKey tag_key = {0};
    DerivedKey data_key = {0};
    status = amiibo_derive_key(&keys.tag, amiibo_data, &tag_key);
    ck_assert_int_eq(status, RFIDX_OK);
    status = amiibo_derive_key(&keys.data, amiibo_data, &data_key);
    ck_assert_int_eq(status, RFIDX_OK);
}
END_TEST

TCase *amiibo_key_io_case(void) {
    TCase *tc = tcase_create("Amiibo Key IO");

    tcase_add_test(tc, test_load_dumped_keys);

    return tc;
}

TCase *amiibo_key_cypher_case(void) {
    TCase *tc = tcase_create("Amiibo Key Cypher");

    tcase_add_test(tc, test_derive_keys);

    return tc;
}
