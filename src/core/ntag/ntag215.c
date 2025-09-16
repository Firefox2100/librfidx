/*
 * librfidx - Universal RFID Tag Format Parser and Converter
 *
 * Copyright (c) 2025. Firefox2100
 *
 * This software is released under the MIT License.
 * SPDX-License-Identifier: MIT
 */

#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <cJSON.h>
#include "librfidx/common.h"
#include "librfidx/ntag/ntag215_core.h"

RfidxStatus ntag215_parse_binary(const uint8_t *buffer, const size_t len, Ntag215Data *ntag215, Ntag21xMetadataHeader *header) {
    if (len == sizeof(Ntag215Data)) {
        memcpy(ntag215, buffer, sizeof(Ntag215Data));
        return RFIDX_OK;
    }

    if (len == sizeof(Ntag21xMetadataHeader) + sizeof(Ntag215Data)) {
        memcpy(header, buffer, sizeof(Ntag21xMetadataHeader));
        memcpy(ntag215, buffer + sizeof(Ntag21xMetadataHeader), sizeof(Ntag215Data));
        return RFIDX_OK;
    }

    return RFIDX_BINARY_FILE_SIZE_ERROR;
}

uint8_t *ntag215_serialize_binary(const Ntag215Data *ntag215, const Ntag21xMetadataHeader *header) {
    uint8_t *buffer = malloc(sizeof(Ntag21xMetadataHeader) + sizeof(Ntag215Data));
    if (!buffer) return NULL;

    memcpy(buffer, header, sizeof(Ntag21xMetadataHeader));
    memcpy(buffer + sizeof(Ntag21xMetadataHeader), ntag215, sizeof(Ntag215Data));
    return buffer;
}

RfidxStatus ntag215_parse_header_from_json(const cJSON *card_obj, Ntag21xMetadataHeader *header) {
    const cJSON *item = cJSON_GetObjectItem(card_obj, "Version");
    if (!item || !item->valuestring) {
        return RFIDX_JSON_PARSE_ERROR;
    }
    if (hex_to_bytes(item->valuestring, header->version, 8) != RFIDX_OK) {
        return RFIDX_JSON_PARSE_ERROR;
    }

    item = cJSON_GetObjectItem(card_obj, "TBO_0");
    if (!item || !item->valuestring) {
        return RFIDX_JSON_PARSE_ERROR;
    }
    if (hex_to_bytes(item->valuestring, header->tbo0, 2) != RFIDX_OK) {
        return RFIDX_JSON_PARSE_ERROR;
    }

    item = cJSON_GetObjectItem(card_obj, "TBO_1");
    if (!item || !item->valuestring) {
        return RFIDX_JSON_PARSE_ERROR;
    }
    if (hex_to_bytes(item->valuestring, &header->tbo1, 1) != RFIDX_OK) {
        return RFIDX_JSON_PARSE_ERROR;
    }

    item = cJSON_GetObjectItem(card_obj, "Signature");
    if (!item || !item->valuestring) {
        return RFIDX_JSON_PARSE_ERROR;
    }
    if (hex_to_bytes(item->valuestring, header->signature, 32) != RFIDX_OK) {
        return RFIDX_JSON_PARSE_ERROR;
    }

    item = cJSON_GetObjectItem(card_obj, "Counter0");
    if (!item || !item->valuestring) {
        return RFIDX_JSON_PARSE_ERROR;
    }
    if (hex_to_bytes(item->valuestring, header->counter0, 3) != RFIDX_OK) {
        return RFIDX_JSON_PARSE_ERROR;
    }

    item = cJSON_GetObjectItem(card_obj, "Tearing0");
    if (!item || !item->valuestring) {
        return RFIDX_JSON_PARSE_ERROR;
    }
    if (hex_to_bytes(item->valuestring, &header->tearing0, 1) != RFIDX_OK) {
        return RFIDX_JSON_PARSE_ERROR;
    }

    item = cJSON_GetObjectItem(card_obj, "Counter1");
    if (!item || !item->valuestring) {
        return RFIDX_JSON_PARSE_ERROR;
    }
    if (hex_to_bytes(item->valuestring, header->counter1, 3) != RFIDX_OK) {
        return RFIDX_JSON_PARSE_ERROR;
    }

    item = cJSON_GetObjectItem(card_obj, "Tearing1");
    if (!item || !item->valuestring) {
        return RFIDX_JSON_PARSE_ERROR;
    }
    if (hex_to_bytes(item->valuestring, &header->tearing1, 1) != RFIDX_OK) {
        return RFIDX_JSON_PARSE_ERROR;
    }

    item = cJSON_GetObjectItem(card_obj, "Counter2");
    if (!item || !item->valuestring) {
        return RFIDX_JSON_PARSE_ERROR;
    }
    if (hex_to_bytes(item->valuestring, header->counter2, 3) != RFIDX_OK) {
        return RFIDX_JSON_PARSE_ERROR;
    }

    item = cJSON_GetObjectItem(card_obj, "Tearing2");
    if (!item || !item->valuestring) {
        return RFIDX_JSON_PARSE_ERROR;
    }
    if (hex_to_bytes(item->valuestring, &header->tearing2, 1) != RFIDX_OK) {
        return RFIDX_JSON_PARSE_ERROR;
    }

    header->memory_max = NTAG215_NUM_PAGES - 1;

    return RFIDX_OK;
}

RfidxStatus ntag215_parse_data_from_json(const cJSON *blocks_obj, Ntag215Data *ntag215) {
    if (!blocks_obj || !ntag215) {
        return RFIDX_JSON_PARSE_ERROR;
    }

    for (int i = 0; i < NTAG215_NUM_USER_PAGES; i++) {
        char idx[8];
        uint_to_str(i, idx, sizeof(idx));
        const cJSON *blk = cJSON_GetObjectItem(blocks_obj, idx);
        if (!blk || !cJSON_IsString(blk)) {
            return RFIDX_JSON_PARSE_ERROR;
        }
        if (hex_to_bytes(blk->valuestring, ntag215->pages[i], 4) != RFIDX_OK) {
            return RFIDX_JSON_PARSE_ERROR;
        }
    }

    return RFIDX_OK;
}

RfidxStatus ntag215_parse_json(const char *json_str, Ntag215Data *ntag215, Ntag21xMetadataHeader *header) {
    cJSON *root = cJSON_Parse(json_str);
    if (!root) {
        return RFIDX_JSON_PARSE_ERROR;
    }

    const cJSON *card_data = cJSON_GetObjectItem(root, "Card");
    if (!card_data) {
        cJSON_Delete(root);
        return RFIDX_JSON_PARSE_ERROR;
    }
    const RfidxStatus header_load_status = ntag215_parse_header_from_json(card_data, header);
    if (header_load_status != RFIDX_OK) {
        cJSON_Delete(root);
        return header_load_status;
    }

    const cJSON *blocks_data = cJSON_GetObjectItem(root, "blocks");
    if (!blocks_data) {
        cJSON_Delete(root);
        return RFIDX_JSON_PARSE_ERROR;
    }
    const RfidxStatus blocks_load_status = ntag215_parse_data_from_json(blocks_data, ntag215);
    if (blocks_load_status != RFIDX_OK) {
        cJSON_Delete(root);
        return blocks_load_status;
    }

    cJSON_Delete(root);

    return RFIDX_OK;
}

cJSON *ntag215_dump_header_to_json(const Ntag21xMetadataHeader *header) {
    cJSON *card_obj = cJSON_CreateObject();
    char hex[65];

    bytes_to_hex(header->version, 8, hex);
    hex[16] = '\0';
    cJSON_AddStringToObject(card_obj, "Version", hex);

    bytes_to_hex(header->tbo0, 2, hex);
    hex[4] = '\0';
    cJSON_AddStringToObject(card_obj, "TBO_0", hex);

    bytes_to_hex(&header->tbo1, 1, hex);
    hex[2] = '\0';
    cJSON_AddStringToObject(card_obj, "TBO_1", hex);

    bytes_to_hex(header->signature, 32, hex);
    hex[64] = '\0';
    cJSON_AddStringToObject(card_obj, "Signature", hex);

    bytes_to_hex(header->counter0, 3, hex);
    hex[6] = '\0';
    cJSON_AddStringToObject(card_obj, "Counter0", hex);
    bytes_to_hex(&header->tearing0, 1, hex);
    hex[2] = '\0';
    cJSON_AddStringToObject(card_obj, "Tearing0", hex);

    bytes_to_hex(header->counter1, 3, hex);
    hex[6] = '\0';
    cJSON_AddStringToObject(card_obj, "Counter1", hex);
    bytes_to_hex(&header->tearing1, 1, hex);
    hex[2] = '\0';
    cJSON_AddStringToObject(card_obj, "Tearing1", hex);

    bytes_to_hex(header->counter2, 3, hex);
    hex[6] = '\0';
    cJSON_AddStringToObject(card_obj, "Counter2", hex);
    bytes_to_hex(&header->tearing2, 1, hex);
    hex[2] = '\0';
    cJSON_AddStringToObject(card_obj, "Tearing2", hex);

    return card_obj;
}

cJSON *ntag215_dump_data_to_json(const Ntag215Data *ntag215) {
    cJSON *blocks_obj = cJSON_CreateObject();
    char hex[9];

    for (int i = 0; i < NTAG215_NUM_PAGES; i++) {
        bytes_to_hex(ntag215->pages[i], 4, hex);
        hex[8] = '\0';
        char idx[8];
        uint_to_str(i, idx, sizeof(idx));
        cJSON_AddStringToObject(blocks_obj, idx, hex);
    }

    return blocks_obj;
}

char *ntag215_serialize_json(const Ntag215Data *ntag215, const Ntag21xMetadataHeader *header) {
    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "Created", JSON_FORMAT_CREATOR);
    cJSON_AddStringToObject(root, "FileType", "mfu");

    cJSON_AddItemToObject(root, "Card", ntag215_dump_header_to_json(header));
    cJSON_AddItemToObject(root, "blocks", ntag215_dump_data_to_json(ntag215));

    char *output = cJSON_Print(root);
    cJSON_Delete(root);

    return output;
}

RfidxStatus ntag215_parse_nfc(const char *nfc_str, Ntag215Data *ntag215, Ntag21xMetadataHeader *header) {
    const char *start = nfc_str;
    const char *end;

    while ((end = strchr(start, '\n')) != NULL) {
        const size_t line_length = end - start;
        char *line = malloc(line_length + 1);
        if (!line) {
            return RFIDX_NFC_PARSE_ERROR;
        }
        strncpy(line, start, line_length);
        line[line_length] = '\0';

        if (line[0] != '#' && line[0] != '\0') {
            char *sep = strchr(line, ':');
            if (sep) {
                *sep = '\0';
                const char *key = line;
                const char *val = sep + 1;
                while (*val && isspace((unsigned char)*val)) val++;

                char *clean = remove_whitespace(val);
                if (!clean) {
                    free(line);
                    return RFIDX_NFC_PARSE_ERROR;
                }

                if (strncmp(key, "Signature", 9) == 0) {
                    if (hex_to_bytes(clean, header->signature, 32) != RFIDX_OK) {
                        free(line);
                        return RFIDX_NFC_PARSE_ERROR;
                    }
                } else if (strncmp(key, "Mifare version", 14) == 0) {
                    if (hex_to_bytes(clean, header->version, 8) != RFIDX_OK) {
                        free(line);
                        return RFIDX_NFC_PARSE_ERROR;
                    }
                } else if (strncmp(key, "Counter 0", 9) == 0) {
                    char *endptr;
                    uint32_t c = (uint32_t) strtoul(val, &endptr, 10);
                    if (val == endptr) {
                        free(line);
                        return RFIDX_NFC_PARSE_ERROR;
                    }
                    header->counter0[0] = (c >> 16) & 0xFF;
                    header->counter0[1] = (c >> 8) & 0xFF;
                    header->counter0[2] = c & 0xFF;
                } else if (strncmp(key, "Tearing 0", 9) == 0) {
                    header->tearing0 = (uint8_t) strtol(val, NULL, 16);
                } else if (strncmp(key, "Counter 1", 9) == 0) {
                    char *endptr;
                    uint32_t c = (uint32_t) strtoul(val, &endptr, 10);
                    if (val == endptr) {
                        free(line);
                        return RFIDX_NFC_PARSE_ERROR;
                    }
                    header->counter1[0] = (c >> 16) & 0xFF;
                    header->counter1[1] = (c >> 8) & 0xFF;
                    header->counter1[2] = c & 0xFF;
                } else if (strncmp(key, "Tearing 1", 9) == 0) {
                    header->tearing1 = (uint8_t) strtol(val, NULL, 16);
                } else if (strncmp(key, "Counter 2", 9) == 0) {
                    char *endptr;
                    uint32_t c = (uint32_t) strtoul(val, &endptr, 10);
                    if (val == endptr) {
                        free(line);
                        return RFIDX_NFC_PARSE_ERROR;
                    }
                    header->counter2[0] = (c >> 16) & 0xFF;
                    header->counter2[1] = (c >> 8) & 0xFF;
                    header->counter2[2] = c & 0xFF;
                } else if (strncmp(key, "Tearing 2", 9) == 0) {
                    header->tearing2 = (uint8_t) strtol(val, NULL, 16);
                } else if (strncmp(key, "Pages total", 11) == 0) {
                    header->memory_max = (uint8_t) strtol(val, NULL, 10) - 1;
                } else if (strncmp(key, "Page ", 5) == 0) {
                    char *endptr;
                    const uint32_t page = (uint32_t)strtoul(key + 5, &endptr, 10);
                    if (val == endptr) {
                        free(line);
                        return RFIDX_NFC_PARSE_ERROR;
                    }
                    if (page < NTAG215_NUM_USER_PAGES) {
                        if (hex_to_bytes(clean, ntag215->pages[page], 4) != RFIDX_OK) {
                            free(line);
                            return RFIDX_NFC_PARSE_ERROR;
                        }
                    }
                }

                free(clean);
            }
        }

        free(line);
        start = end + 1;
    }

    return RFIDX_OK;
}

char *ntag215_serialize_nfc(const Ntag215Data *ntag215, const Ntag21xMetadataHeader *header) {
    size_t cap = 1024;
    size_t len = 0;
    char *buf = malloc(cap);
    if (!buf) return NULL;
    buf[0] = '\0';

    appendf(&buf, &len, &cap, "Filetype: Flipper NFC device\n");
    appendf(&buf, &len, &cap, "Version: 2\n");
    appendf(&buf, &len, &cap, "Device type: NTAG215\n");
    appendf(&buf, &len, &cap, "UID: %02X %02X %02X %02X %02X %02X %02X\n",
            ntag215->structure.manufacturer_data.uid0[0],
            ntag215->structure.manufacturer_data.uid0[1],
            ntag215->structure.manufacturer_data.uid0[2],
            ntag215->structure.manufacturer_data.uid1[0],
            ntag215->structure.manufacturer_data.uid1[1],
            ntag215->structure.manufacturer_data.uid1[2],
            ntag215->structure.manufacturer_data.uid1[3]);

    appendf(&buf, &len, &cap, "ATQA: 00 44\n");
    appendf(&buf, &len, &cap, "SAK: 00\n");

    appendf(&buf, &len, &cap, "Signature:");
    for (int i = 0; i < 32; i++) appendf(&buf, &len, &cap, " %02X", header->signature[i]);
    appendf(&buf, &len, &cap, "\n");

    appendf(&buf, &len, &cap, "Mifare version:");
    for (int i = 0; i < 8; i++) appendf(&buf, &len, &cap, " %02X", header->version[i]);
    appendf(&buf, &len, &cap, "\n");

    const uint32_t c0 = (header->counter0[0] << 16) | (header->counter0[1] << 8) | header->counter0[2];
    appendf(&buf, &len, &cap, "Counter 0: %u\n", c0);
    appendf(&buf, &len, &cap, "Tearing 0: %02X\n", header->tearing0);

    const uint32_t c1 = (header->counter1[0] << 16) | (header->counter1[1] << 8) | header->counter1[2];
    appendf(&buf, &len, &cap, "Counter 1: %u\n", c1);
    appendf(&buf, &len, &cap, "Tearing 1: %02X\n", header->tearing1);

    const uint32_t c2 = (header->counter2[0] << 16) | (header->counter2[1] << 8) | header->counter2[2];
    appendf(&buf, &len, &cap, "Counter 2: %u\n", c2);
    appendf(&buf, &len, &cap, "Tearing 2: %02X\n", header->tearing2);

    appendf(&buf, &len, &cap, "Pages total: %d\n", header->memory_max + 1);

    for (int i = 0; i < NTAG215_NUM_PAGES; i++) {
        appendf(&buf, &len, &cap, "Page %d: %02X %02X %02X %02X\n", i,
                ntag215->pages[i][0],
                ntag215->pages[i][1],
                ntag215->pages[i][2],
                ntag215->pages[i][3]);
    }

    appendf(&buf, &len, &cap, "Failed authentication attempts: 0\n");

    return buf;
}

RfidxStatus ntag215_generate(Ntag215Data* ntag215, Ntag21xMetadataHeader *header) {
    // Re-initialize the memory space
    memset(ntag215, 0, sizeof(Ntag215Data));
    memset(header, 0, sizeof(Ntag21xMetadataHeader));

    // Generate UID
    ntag21x_randomize_uid(&ntag215->structure.manufacturer_data);

    return RFIDX_OK;
}

RfidxStatus ntag215_wipe(Ntag215Data* ntag215) {
    // Reset all user memory pages
    for (int i = 0; i < NTAG215_NUM_USER_PAGES; i++) {
        memset(ntag215->structure.user_memory[i], 0, NTAG21X_PAGE_SIZE);
    }

    // Unlock all pages and wipe the password
    memset(ntag215->structure.configuration.passwd, 0, 4);
    memset(ntag215->structure.configuration.pack, 0, 2);
    memset(ntag215->structure.dynamic_lock, 0, 3);

    return RFIDX_OK;
}

RfidxStatus ntag215_transform_data(
    Ntag215Data **ntag215,
    Ntag21xMetadataHeader **header,
    const TransformCommand command
) {
    switch (command) {
        case TRANSFORM_NONE:
            return RFIDX_OK;
        case TRANSFORM_WIPE:
            return ntag215_wipe(*ntag215);
        case TRANSFORM_GENERATE:
            *ntag215 = malloc(sizeof(Ntag215Data));
            if (!*ntag215) return RFIDX_MEMORY_ERROR;

            *header = malloc(sizeof(Ntag21xMetadataHeader));
            if (!*header) {
                free(*ntag215);
                return RFIDX_MEMORY_ERROR;
            }

            return ntag215_generate(*ntag215, *header);
        case TRANSFORM_RANDOMIZE_UID:
            return ntag21x_randomize_uid(&(*ntag215)->structure.manufacturer_data);
        default:
            return RFIDX_UNKNOWN_ENUM_ERROR;
    }
}
