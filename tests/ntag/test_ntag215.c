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
#include <cJSON.h>
#include <cmocka.h>
#include "librfidx/ntag/ntag215.h"

RfidxStatus ntag215_parse_header_from_json(const cJSON *card_obj, Ntag21xMetadataHeader *header);
RfidxStatus ntag215_parse_data_from_json(const cJSON *blocks_obj, Ntag215Data *ntag215);
cJSON *ntag215_dump_header_to_json(const Ntag21xMetadataHeader *header);
cJSON *ntag215_dump_data_to_json(const Ntag215Data *ntag215);

static char *read_file(const char *filename) {
    FILE *fp = fopen(filename, "rb");
    assert_non_null(fp);
    assert_int_equal(fseek(fp, 0, SEEK_END), 0);
    const long len = ftell(fp);
    assert_true(len >= 0);
    rewind(fp);
    char *buf = malloc((size_t)len + 1);
    assert_non_null(buf);
    assert_int_equal((long)fread(buf, 1, (size_t)len, fp), len);
    buf[len] = '\0';
    fclose(fp);
    return buf;
}

static cJSON *create_blocks_object(void) {
    cJSON *blocks = cJSON_CreateObject();
    for (int i = 0; i < NTAG215_NUM_USER_PAGES; i++) {
        char key[8];
        snprintf(key, sizeof(key), "%d", i);
        char value[9];
        snprintf(value, sizeof(value), "%08X", i);
        cJSON_AddStringToObject(blocks, key, value);
    }
    return blocks;
}

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

static const char header_json_base[] =
    "{"
    "\"Version\":\"0004040201001103\","
    "\"TBO_0\":\"0000\","
    "\"TBO_1\":\"00\","
    "\"Signature\":\"0000000000000000000000000000000000000000000000000000000000000000\","
    "\"Counter0\":\"000000\","
    "\"Tearing0\":\"00\","
    "\"Counter1\":\"000000\","
    "\"Tearing1\":\"00\","
    "\"Counter2\":\"000000\","
    "\"Tearing2\":\"00\""
    "}";

static void test_ntag215_parse_binary_data_only(void **state) {
    (void) state;
    Ntag215Data src = {0};
    memset(&src, 0x11, sizeof(src));
    Ntag215Data dst = {0};
    Ntag21xMetadataHeader header;
    memset(&header, 0xAA, sizeof(header));
    RfidxStatus status = ntag215_parse_binary((uint8_t*)&src, sizeof(Ntag215Data), &dst, &header);
    assert_int_equal(status, RFIDX_OK);
    assert_memory_equal(&dst, &src, sizeof(Ntag215Data));
    for (size_t i = 0; i < sizeof(Ntag21xMetadataHeader); i++) {
        assert_int_equal(((uint8_t*)&header)[i], 0xAA);
    }
}

static void test_ntag215_parse_binary_with_header(void **state) {
    (void) state;
    Ntag215Data src_data = {0};
    Ntag21xMetadataHeader src_header = {0};
    memset(&src_data, 0x22, sizeof(src_data));
    memset(&src_header, 0x33, sizeof(src_header));
    uint8_t *buffer = malloc(sizeof(src_header) + sizeof(src_data));
    memcpy(buffer, &src_header, sizeof(src_header));
    memcpy(buffer + sizeof(src_header), &src_data, sizeof(src_data));
    Ntag215Data dst_data = {0};
    Ntag21xMetadataHeader dst_header = {0};
    RfidxStatus status = ntag215_parse_binary(buffer, sizeof(src_header) + sizeof(src_data), &dst_data, &dst_header);
    assert_int_equal(status, RFIDX_OK);
    assert_memory_equal(&dst_header, &src_header, sizeof(src_header));
    assert_memory_equal(&dst_data, &src_data, sizeof(src_data));
    free(buffer);
}

static void test_ntag215_parse_binary_invalid_length(void **state) {
    (void) state;
    uint8_t buffer[10] = {0};
    Ntag215Data data = {0};
    Ntag21xMetadataHeader header = {0};
    const RfidxStatus status = ntag215_parse_binary(buffer, sizeof(buffer), &data, &header);
    assert_int_equal(status, RFIDX_BINARY_FILE_SIZE_ERROR);
}

static void test_ntag215_serialize_binary(void **state) {
    (void) state;
    Ntag215Data data = {0};
    Ntag21xMetadataHeader header = {0};
    memset(&data, 0x44, sizeof(data));
    memset(&header, 0x55, sizeof(header));
    uint8_t *buf = ntag215_serialize_binary(&data, &header);
    assert_non_null(buf);
    assert_memory_equal(buf, &header, sizeof(header));
    assert_memory_equal(buf + sizeof(header), &data, sizeof(data));
    // free(buf);
}

static void test_ntag215_parse_header_from_json_success(void **state) {
    (void) state;
    cJSON *card = cJSON_Parse(header_json_base);
    assert_non_null(card);
    Ntag21xMetadataHeader header = {0};
    const RfidxStatus status = ntag215_parse_header_from_json(card, &header);
    assert_int_equal(status, RFIDX_OK);
    assert_header_correct(&header);
    cJSON_Delete(card);
}

static void test_ntag215_parse_header_from_json_missing_fields(void **state) {
    (void) state;
    const char *fields[] = {"Version", "TBO_0", "TBO_1", "Signature", "Counter0", "Tearing0", "Counter1", "Tearing1", "Counter2", "Tearing2"};
    for (size_t i = 0; i < sizeof(fields)/sizeof(fields[0]); i++) {
        cJSON *card = cJSON_Parse(header_json_base);
        cJSON_DeleteItemFromObject(card, fields[i]);
        Ntag21xMetadataHeader header;
        const RfidxStatus status = ntag215_parse_header_from_json(card, &header);
        assert_int_equal(status, RFIDX_JSON_PARSE_ERROR);
        cJSON_Delete(card);
    }
}

static void test_ntag215_parse_header_from_json_invalid_hex(void **state) {
    (void) state;
    cJSON *card = cJSON_Parse(header_json_base);
    cJSON *ver = cJSON_GetObjectItem(card, "Version");
    cJSON_SetValuestring(ver, "GG");
    Ntag21xMetadataHeader header;
    const RfidxStatus status = ntag215_parse_header_from_json(card, &header);
    assert_int_equal(status, RFIDX_JSON_PARSE_ERROR);
    cJSON_Delete(card);
}

static void test_ntag215_parse_data_from_json_success(void **state) {
    (void) state;
    cJSON *blocks = create_blocks_object();
    Ntag215Data data = {0};
    const RfidxStatus status = ntag215_parse_data_from_json(blocks, &data);
    assert_int_equal(status, RFIDX_OK);
    assert_int_equal(data.pages[5][3], 5);
    assert_int_equal(data.pages[125][3], 125);
    cJSON_Delete(blocks);
}

static void test_ntag215_parse_data_from_json_missing_or_invalid(void **state) {
    (void) state;
    // Missing block
    cJSON *blocks = create_blocks_object();
    cJSON_DeleteItemFromObject(blocks, "5");
    Ntag215Data data = {0};
    RfidxStatus status = ntag215_parse_data_from_json(blocks, &data);
    assert_int_equal(status, RFIDX_JSON_PARSE_ERROR);
    cJSON_Delete(blocks);

    // Invalid hex
    blocks = create_blocks_object();
    cJSON_ReplaceItemInObject(blocks, "5", cJSON_CreateString("GGGGGGGG"));
    status = ntag215_parse_data_from_json(blocks, &data);
    assert_int_equal(status, RFIDX_JSON_PARSE_ERROR);
    cJSON_Delete(blocks);

    // Null parameters
    status = ntag215_parse_data_from_json(NULL, &data);
    assert_int_equal(status, RFIDX_JSON_PARSE_ERROR);
    blocks = create_blocks_object();
    status = ntag215_parse_data_from_json(blocks, NULL);
    assert_int_equal(status, RFIDX_JSON_PARSE_ERROR);
    cJSON_Delete(blocks);
}

static cJSON *create_full_json(void) {
    cJSON *root = cJSON_CreateObject();
    cJSON *card = cJSON_Parse(header_json_base);
    cJSON_AddItemToObject(root, "Card", card);
    cJSON *blocks = create_blocks_object();
    cJSON_AddItemToObject(root, "blocks", blocks);
    return root;
}

static void test_ntag215_parse_json_success(void **state) {
    (void) state;
    cJSON *root = create_full_json();
    char *json = cJSON_PrintUnformatted(root);
    Ntag215Data data = {0};
    Ntag21xMetadataHeader header = {0};
    const RfidxStatus status = ntag215_parse_json(json, &data, &header);
    assert_int_equal(status, RFIDX_OK);
    assert_header_correct(&header);
    assert_int_equal(data.pages[5][3], 5);
    // free(json);
    cJSON_Delete(root);
}

static void test_ntag215_parse_json_errors(void **state) {
    (void) state;
    Ntag215Data data = {0};
    Ntag21xMetadataHeader header = {0};

    // Missing Card
    cJSON *root = create_full_json();
    cJSON_DeleteItemFromObject(root, "Card");
    char *json = cJSON_PrintUnformatted(root);
    RfidxStatus status = ntag215_parse_json(json, &data, &header);
    assert_int_equal(status, RFIDX_JSON_PARSE_ERROR);
    // free(json);
    cJSON_Delete(root);

    // Header error
    root = create_full_json();
    cJSON *card = cJSON_GetObjectItem(root, "Card");
    cJSON_DeleteItemFromObject(card, "Version");
    json = cJSON_PrintUnformatted(root);
    status = ntag215_parse_json(json, &data, &header);
    assert_int_equal(status, RFIDX_JSON_PARSE_ERROR);
    // free(json);
    cJSON_Delete(root);

    // Missing blocks
    root = create_full_json();
    cJSON_DeleteItemFromObject(root, "blocks");
    json = cJSON_PrintUnformatted(root);
    status = ntag215_parse_json(json, &data, &header);
    assert_int_equal(status, RFIDX_JSON_PARSE_ERROR);
    // free(json);
    cJSON_Delete(root);

    // Blocks error
    root = create_full_json();
    cJSON *blocks = cJSON_GetObjectItem(root, "blocks");
    cJSON_ReplaceItemInObject(blocks, "5", cJSON_CreateString("GGGGGGGG"));
    json = cJSON_PrintUnformatted(root);
    status = ntag215_parse_json(json, &data, &header);
    assert_int_equal(status, RFIDX_JSON_PARSE_ERROR);
    // free(json);
    cJSON_Delete(root);

    // Invalid JSON
    status = ntag215_parse_json("not json", &data, &header);
    assert_int_equal(status, RFIDX_JSON_PARSE_ERROR);
}

static void test_ntag215_dump_header_to_json(void **state) {
    (void) state;
    Ntag21xMetadataHeader header = {0};
    header.memory_max = NTAG215_NUM_PAGES - 1;
    cJSON *card = ntag215_dump_header_to_json(&header);
    assert_non_null(card);
    cJSON *version = cJSON_GetObjectItem(card, "Version");
    assert_string_equal(version->valuestring, "0000000000000000");
    cJSON_Delete(card);
}

static void test_ntag215_dump_data_to_json(void **state) {
    (void) state;
    Ntag215Data data = {0};
    data.pages[0][0] = 0xAA;
    cJSON *blocks = ntag215_dump_data_to_json(&data);
    assert_non_null(blocks);
    cJSON *p0 = cJSON_GetObjectItem(blocks, "0");
    assert_string_equal(p0->valuestring, "AA000000");
    cJSON_Delete(blocks);
}

static void test_ntag215_serialize_json(void **state) {
    (void) state;
    Ntag215Data data = {0};
    Ntag21xMetadataHeader header = {0};
    header.memory_max = NTAG215_NUM_PAGES - 1;
    char *json = ntag215_serialize_json(&data, &header);
    assert_non_null(json);
    assert_non_null(strstr(json, "\"Card\""));
    // free(json);
}

static void test_ntag215_parse_nfc_success(void **state) {
    (void) state;
    char *nfc = read_file("tests/assets/ntag215.nfc");
    Ntag215Data data = {0};
    Ntag21xMetadataHeader header = {0};
    const RfidxStatus status = ntag215_parse_nfc(nfc, &data, &header);
    assert_int_equal(status, RFIDX_OK);
    assert_int_equal(data.pages[0][0], 0x04);
    free(nfc);
}

static void test_ntag215_parse_nfc_errors(void **state) {
    (void) state;
    Ntag215Data data = {0};
    Ntag21xMetadataHeader header = {0};

    char *nfc = read_file("tests/assets/ntag215.nfc");
    char *sig = strstr(nfc, "Signature:");
    assert_non_null(sig);
    char *p = strchr(sig, ':');
    p += 2; // skip ':' and space
    p[0] = 'G';
    p[1] = 'G';
    RfidxStatus status = ntag215_parse_nfc(nfc, &data, &header);
    assert_int_equal(status, RFIDX_NFC_PARSE_ERROR);
    free(nfc);

    nfc = read_file("tests/assets/ntag215.nfc");
    char *ctr = strstr(nfc, "Counter 0:");
    assert_non_null(ctr);
    p = strchr(ctr, ':');
    p += 1; // position at space before number
    p[1] = 'x';
    status = ntag215_parse_nfc(nfc, &data, &header);
    assert_int_equal(status, RFIDX_NFC_PARSE_ERROR);
    free(nfc);
}

static void test_ntag215_serialize_nfc(void **state) {
    (void) state;
    Ntag215Data data = {0};
    Ntag21xMetadataHeader header = {0};
    header.memory_max = NTAG215_NUM_PAGES - 1;
    char *nfc = ntag215_serialize_nfc(&data, &header);
    assert_non_null(nfc);
    assert_non_null(strstr(nfc, "Filetype: Flipper NFC device"));
    // free(nfc);
}

static void test_ntag215_generate_success(void **state) {
    (void) state;
    Ntag215Data data;
    Ntag21xMetadataHeader header;
    RfidxStatus status = rfidx_init_rng(NULL, NULL);
    assert_int_equal(status, RFIDX_OK);
    status = ntag215_generate(&data, &header);
    assert_int_equal(status, RFIDX_OK);
    assert_int_equal(header.memory_max, 0);
    status = rfidx_free_rng();
    assert_int_equal(status, RFIDX_OK);
}

static void test_ntag215_wipe(void **state) {
    (void) state;
    Ntag215Data data;
    memset(&data, 0xFF, sizeof(data));
    const RfidxStatus status = ntag215_wipe(&data);
    assert_int_equal(status, RFIDX_OK);
    for (int i = 0; i < NTAG215_NUM_USER_PAGES; i++) {
        assert_memory_equal(data.structure.user_memory[i], (uint8_t[4]){0}, 4);
    }
    assert_memory_equal(data.structure.configuration.passwd, (uint8_t[4]){0}, 4);
}

static void test_ntag215_transform_data_none(void **state) {
    (void) state;
    Ntag215Data data = {0};
    Ntag21xMetadataHeader header = {0};
    Ntag215Data *pdata = &data;
    Ntag21xMetadataHeader *pheader = &header;
    const RfidxStatus status = ntag215_transform_data(&pdata, &pheader, TRANSFORM_NONE);
    assert_int_equal(status, RFIDX_OK);
}

static void test_ntag215_transform_data_wipe(void **state) {
    (void) state;
    Ntag215Data data;
    memset(&data, 0xFF, sizeof(data));
    Ntag21xMetadataHeader header = {0};
    Ntag215Data *pdata = &data;
    Ntag21xMetadataHeader *pheader = &header;
    const RfidxStatus status = ntag215_transform_data(&pdata, &pheader, TRANSFORM_WIPE);
    assert_int_equal(status, RFIDX_OK);
    for (int i = 0; i < NTAG215_NUM_USER_PAGES; i++) {
        assert_memory_equal(pdata->structure.user_memory[i], (uint8_t[4]){0}, 4);
    }
}

static void test_ntag215_transform_data_generate(void **state) {
    (void) state;
    Ntag215Data *data = NULL;
    Ntag21xMetadataHeader *header = NULL;
    RfidxStatus status = rfidx_init_rng(NULL, NULL);
    assert_int_equal(status, RFIDX_OK);
    status = ntag215_transform_data(&data, &header, TRANSFORM_GENERATE);
    assert_int_equal(status, RFIDX_OK);
    assert_non_null(data);
    assert_non_null(header);
    // free(data);
    // free(header);
    rfidx_free_rng();
}

static void test_ntag215_transform_data_randomize_uid_success(void **state) {
    (void) state;
    Ntag215Data data = {0};
    Ntag21xMetadataHeader header = {0};
    Ntag215Data *pdata = &data;
    Ntag21xMetadataHeader *pheader = &header;
    RfidxStatus status = rfidx_init_rng(NULL, NULL);
    assert_int_equal(status, RFIDX_OK);
    status = ntag215_transform_data(&pdata, &pheader, TRANSFORM_RANDOMIZE_UID);
    assert_int_equal(status, RFIDX_OK);
    rfidx_free_rng();
}

static void test_ntag215_transform_data_randomize_uid_failure(void **state) {
    (void) state;
    Ntag215Data data = {0};
    Ntag21xMetadataHeader header = {0};
    Ntag215Data *pdata = &data;
    Ntag21xMetadataHeader *pheader = &header;
    const RfidxStatus status = ntag215_transform_data(&pdata, &pheader, TRANSFORM_RANDOMIZE_UID);
    assert_int_equal(status, RFIDX_DRNG_ERROR);
}

static void test_ntag215_transform_data_unknown(void **state) {
    (void) state;
    Ntag215Data data = {0};
    Ntag21xMetadataHeader header = {0};
    Ntag215Data *pdata = &data;
    Ntag21xMetadataHeader *pheader = &header;
    const RfidxStatus status = ntag215_transform_data(&pdata, &pheader, (TransformCommand)99);
    assert_int_equal(status, RFIDX_UNKNOWN_ENUM_ERROR);
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
    cmocka_unit_test(test_ntag215_parse_binary_data_only),
    cmocka_unit_test(test_ntag215_parse_binary_with_header),
    cmocka_unit_test(test_ntag215_parse_binary_invalid_length),
    cmocka_unit_test(test_ntag215_serialize_binary),
    cmocka_unit_test(test_ntag215_parse_header_from_json_success),
    cmocka_unit_test(test_ntag215_parse_header_from_json_missing_fields),
    cmocka_unit_test(test_ntag215_parse_header_from_json_invalid_hex),
    cmocka_unit_test(test_ntag215_parse_data_from_json_success),
    cmocka_unit_test(test_ntag215_parse_data_from_json_missing_or_invalid),
    cmocka_unit_test(test_ntag215_parse_json_success),
    cmocka_unit_test(test_ntag215_parse_json_errors),
    cmocka_unit_test(test_ntag215_dump_header_to_json),
    cmocka_unit_test(test_ntag215_dump_data_to_json),
    cmocka_unit_test(test_ntag215_serialize_json),
    cmocka_unit_test(test_ntag215_parse_nfc_success),
    cmocka_unit_test(test_ntag215_parse_nfc_errors),
    cmocka_unit_test(test_ntag215_serialize_nfc),
    cmocka_unit_test(test_ntag215_generate_success),
    cmocka_unit_test(test_ntag215_wipe),
    cmocka_unit_test(test_ntag215_transform_data_none),
    cmocka_unit_test(test_ntag215_transform_data_wipe),
    cmocka_unit_test(test_ntag215_transform_data_generate),
    cmocka_unit_test(test_ntag215_transform_data_randomize_uid_success),
    cmocka_unit_test(test_ntag215_transform_data_randomize_uid_failure),
    cmocka_unit_test(test_ntag215_transform_data_unknown),
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
