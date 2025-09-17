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
#include "librfidx/mifare/mifare_classic_1k_core.h"

RfidxStatus mfc1k_parse_binary(
    const uint8_t *buffer,
    const size_t len,
    Mfc1kData *mfc1k,
    MfcMetadataHeader *header) {
    memcpy(mfc1k, buffer, sizeof(Mfc1kData));

    // Headers are not present in binary dumps, but all bytes are known
    header->atqa[0] = 0x00;
    header->atqa[1] = 0x04; // Mifare Classic
    header->sak = 0x08; // Mifare Classic 1K

    // Always assume a 4-byte NUID
    memcpy(header->uid, mfc1k->manufacturer_data_4b.nuid, 4);
    header->uid[4] = 0x00;
    header->uid[5] = 0x00;
    header->uid[6] = 0x00;

    return RFIDX_OK;
}

uint8_t *mfc1k_serialize_binary(const Mfc1kData *mfc1k, const MfcMetadataHeader *header) {
    uint8_t *buffer = malloc(sizeof(Mfc1kData));
    if (!buffer) return NULL;

    memcpy(buffer, mfc1k, sizeof(Mfc1kData));
    return buffer;
}

RfidxStatus mfc1k_parse_header_from_json(const cJSON *card_obj, MfcMetadataHeader *header) {
    const cJSON *item = cJSON_GetObjectItem(card_obj, "UID");
    if (!item || !item->valuestring) {
        return RFIDX_JSON_PARSE_ERROR;
    }
    // Check the length of the string first to determine if it's 4-byte NUID or 7-byte UID
    const size_t uid_len = strnlen(item->valuestring, 15);
    if (uid_len == 8) {
        // 4-byte NUID
        if (hex_to_bytes(item->valuestring, header->uid, 4) != RFIDX_OK) {
            return RFIDX_JSON_PARSE_ERROR;
        }
        header->uid[4] = 0x00;
        header->uid[5] = 0x00;
        header->uid[6] = 0x00;
    } else if (uid_len == 14) {
        // 7-byte UID
        if (hex_to_bytes(item->valuestring, header->uid, 7) != RFIDX_OK) {
            return RFIDX_JSON_PARSE_ERROR;
        }
    } else {
        return RFIDX_JSON_PARSE_ERROR;
    }

    item = cJSON_GetObjectItem(card_obj, "ATQA");
    if (!item || !item->valuestring) {
        return RFIDX_JSON_PARSE_ERROR;
    }
    if (hex_to_bytes(item->valuestring, header->atqa, 2) != RFIDX_OK) {
        return RFIDX_JSON_PARSE_ERROR;
    }

    item = cJSON_GetObjectItem(card_obj, "SAK");
    if (!item || !item->valuestring) {
        return RFIDX_JSON_PARSE_ERROR;
    }
    if (hex_to_bytes(item->valuestring, &header->sak, 1) != RFIDX_OK) {
        return RFIDX_JSON_PARSE_ERROR;
    }

    return RFIDX_OK;
}

RfidxStatus mfc1k_parse_data_from_json(const cJSON *blocks_obj, Mfc1kData *mfc1k) {
    if (!blocks_obj || !mfc1k) {
        return RFIDX_JSON_PARSE_ERROR;
    }

    for (int i = 0; i < MFC_1K_NUM_SECTOR; i++) {
        for (int j = 0; j < MFC_1K_NUM_BLOCK_PER_SECTOR; j++) {
            char idx[8];
            uint_to_str(i * MFC_1K_NUM_BLOCK_PER_SECTOR + j, idx, sizeof(idx));
            const cJSON *blk = cJSON_GetObjectItem(blocks_obj, idx);
            if (!blk || !cJSON_IsString(blk)) {
                return RFIDX_JSON_PARSE_ERROR;
            }

            if (hex_to_bytes(blk->valuestring, mfc1k->blocks[i][j], MFC_1K_BLOCK_SIZE) != RFIDX_OK) {
                return RFIDX_JSON_PARSE_ERROR;
            }
        }
    }

    return RFIDX_OK;
}

RfidxStatus mfc1k_parse_json(const char *json_str, Mfc1kData *mfc1k, MfcMetadataHeader *header) {
    cJSON *root = cJSON_Parse(json_str);
    if (!root) {
        return RFIDX_JSON_PARSE_ERROR;
    }

    const cJSON *card_data = cJSON_GetObjectItem(root, "Card");
    if (!card_data) {
        cJSON_Delete(root);
        return RFIDX_JSON_PARSE_ERROR;
    }
    const RfidxStatus header_load_status = mfc1k_parse_header_from_json(card_data, header);
    if (header_load_status != RFIDX_OK) {
        cJSON_Delete(root);
        return header_load_status;
    }

    const cJSON *blocks_data = cJSON_GetObjectItem(root, "blocks");
    if (!blocks_data) {
        cJSON_Delete(root);
        return RFIDX_JSON_PARSE_ERROR;
    }
    const RfidxStatus blocks_load_status = mfc1k_parse_data_from_json(blocks_data, mfc1k);
    if (blocks_load_status != RFIDX_OK) {
        cJSON_Delete(root);
        return blocks_load_status;
    }

    // The keys section in the JSON is redundant, because all keys are stored in the sector trailers.
    // Ignore for now.
    cJSON_Delete(root);

    return RFIDX_OK;
}

cJSON *mfc1k_dump_header_to_json(const MfcMetadataHeader *header) {
    cJSON *card_obj = cJSON_CreateObject();
    char hex[65];

    // Check the size of UID to determine if it's 4-byte NUID or 7-byte UID
    if (header->uid[4] == 0x00 && header->uid[5] == 0x00 && header->uid[6] == 0x00) {
        // 4-byte NUID
        bytes_to_hex(header->uid, 4, hex);
        hex[8] = '\0';
    } else {
        // 7-byte UID
        bytes_to_hex(header->uid, 7, hex);
        hex[14] = '\0';
    }
    cJSON_AddStringToObject(card_obj, "UID", hex);

    bytes_to_hex(header->atqa, 2, hex);
    hex[4] = '\0';
    cJSON_AddStringToObject(card_obj, "ATQA", hex);

    bytes_to_hex(&header->sak, 1, hex);
    hex[2] = '\0';
    cJSON_AddStringToObject(card_obj, "SAK", hex);

    return card_obj;
}

cJSON *mfc1k_dump_data_to_json(const Mfc1kData *mfc1k) {
    cJSON *blocks_obj = cJSON_CreateObject();
    char hex[MFC_1K_BLOCK_SIZE * 2 + 1];

    for (int i = 0; i < MFC_1K_NUM_SECTOR; i++) {
        for (int j = 0; j < MFC_1K_NUM_BLOCK_PER_SECTOR; j++) {
            char idx[8];
            uint_to_str(i * MFC_1K_NUM_BLOCK_PER_SECTOR + j, idx, sizeof(idx));

            bytes_to_hex(mfc1k->blocks[i][j], MFC_1K_BLOCK_SIZE, hex);
            hex[MFC_1K_BLOCK_SIZE * 2] = '\0';
            cJSON_AddStringToObject(blocks_obj, idx, hex);
        }
    }

    return blocks_obj;
}

cJSON *mfc1k_dump_keys_to_json(const Mfc1kData *mfc1k) {
    cJSON *keys_obj = cJSON_CreateObject();

    for (int i = 0; i < MFC_1K_NUM_SECTOR; i++) {
        char idx[8];
        uint_to_str(i, idx, sizeof(idx));

        cJSON *sector_obj = cJSON_CreateObject();
        char hex[13];

        bytes_to_hex(mfc1k->structure.sector[i].sector_trailer.key_a, 6, hex);
        hex[12] = '\0';
        cJSON_AddStringToObject(sector_obj, "KeyA", hex);

        bytes_to_hex(mfc1k->structure.sector[i].sector_trailer.key_b, 6, hex);
        hex[12] = '\0';
        cJSON_AddStringToObject(sector_obj, "KeyB", hex);

        bytes_to_hex(mfc1k->structure.sector[i].sector_trailer.access_bits, 4, hex);
        bytes_to_hex(&mfc1k->structure.sector[i].sector_trailer.user_data, 1, hex + 8);
        hex[10] = '\0';
        cJSON_AddStringToObject(sector_obj, "AccessConditions", hex);

        // The AccessConditionsText does not seem to be parsed by proxmark 3, so skipping it now
        cJSON_AddItemToObject(keys_obj, idx, sector_obj);
    }

    return keys_obj;
}

char *mfc1k_serialize_json(const Mfc1kData *mfc1k, const MfcMetadataHeader *header) {
    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "Created", JSON_FORMAT_CREATOR);
    cJSON_AddStringToObject(root, "FileType", "mfc v2");

    cJSON_AddItemToObject(root, "Card", mfc1k_dump_header_to_json(header));
    cJSON_AddItemToObject(root, "blocks", mfc1k_dump_data_to_json(mfc1k));
    cJSON_AddItemToObject(root, "SectorKeys", mfc1k_dump_keys_to_json(mfc1k));

    char *output = cJSON_Print(root);
    cJSON_Delete(root);

    return output;
}

RfidxStatus mfc1k_parse_nfc(const char *nfc_str, Mfc1kData *mfc1k, MfcMetadataHeader *header) {
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

                if (strncmp(key, "UID", 3) == 0) {
                    // Check the length of the string first to determine if it's 4-byte NUID or 7-byte UID
                    const size_t uid_len = strnlen(clean, 15);
                    if (uid_len == 8) {
                        // 4-byte NUID
                        if (hex_to_bytes(clean, header->uid, 4) != RFIDX_OK) {
                            free(line);
                            return RFIDX_NFC_PARSE_ERROR;
                        }
                        header->uid[4] = 0x00;
                        header->uid[5] = 0x00;
                        header->uid[6] = 0x00;
                    } else if (uid_len == 14) {
                        // 7-byte UID
                        if (hex_to_bytes(clean, header->uid, 7) != RFIDX_OK) {
                            free(line);
                            return RFIDX_NFC_PARSE_ERROR;
                        }
                    } else {
                        free(line);
                        return RFIDX_NFC_PARSE_ERROR;
                    }
                } else if (strncmp(key, "ATQA", 4) == 0) {
                    if (hex_to_bytes(clean, header->atqa, 2) != RFIDX_OK) {
                        free(line);
                        return RFIDX_NFC_PARSE_ERROR;
                    }
                } else if (strncmp(key, "SAK", 3) == 0) {
                    if (hex_to_bytes(clean, &header->sak, 1) != RFIDX_OK) {
                        free(line);
                        return RFIDX_NFC_PARSE_ERROR;
                    }
                } else if (strncmp(key, "Block ", 6) == 0) {
                    char *endptr;
                    const uint32_t page = (uint32_t) strtoul(key + 5, &endptr, 10);
                    if (val == endptr) {
                        free(line);
                        return RFIDX_NFC_PARSE_ERROR;
                    }
                    if (page < MFC_1K_NUM_BLOCK_PER_SECTOR * MFC_1K_NUM_SECTOR) {
                        const uint32_t idx_sector = page / MFC_1K_NUM_BLOCK_PER_SECTOR;
                        const uint32_t idx_block = page % MFC_1K_NUM_BLOCK_PER_SECTOR;

                        if (hex_to_bytes(clean, mfc1k->blocks[idx_sector][idx_block], MFC_1K_BLOCK_SIZE) != RFIDX_OK) {
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

char *mfc1k_serialize_nfc(const Mfc1kData *mfc1k, const MfcMetadataHeader *header) {
    size_t cap = 1024;
    size_t len = 0;
    char *buf = malloc(cap);
    if (!buf) return NULL;
    buf[0] = '\0';

    appendf(&buf, &len, &cap, "Filetype: Flipper NFC device\n");
    appendf(&buf, &len, &cap, "Version: 4\n");
    appendf(&buf, &len, &cap, "Device type: Mifare Classic\n");

    if (header->uid[4] == 0x00 && header->uid[5] == 0x00 && header->uid[6] == 0x00) {
        // 4-byte NUID
        appendf(&buf, &len, &cap, "UID: %02X %02X %02X %02X\n",
                header->uid[0], header->uid[1], header->uid[2], header->uid[3]);
    } else {
        // 7-byte UID
        appendf(&buf, &len, &cap, "UID: %02X %02X %02X %02X %02X %02X %02X\n",
                header->uid[0], header->uid[1], header->uid[2],
                header->uid[3], header->uid[4], header->uid[5], header->uid[6]);
    }

    appendf(&buf, &len, &cap, "ATQA: %02X %02X\n", header->atqa[0], header->atqa[1]);
    appendf(&buf, &len, &cap, "SAK: %02X\n", header->sak);

    appendf(&buf, &len, &cap, "Mifare Classic type: 1K\nData format version: 2\n");

    for (int i = 0; i < MFC_1K_NUM_SECTOR; i++) {
        for (int j = 0; j < MFC_1K_NUM_BLOCK_PER_SECTOR; j++) {
            appendf(&buf, &len, &cap,
                    "Block %d: %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X\n",
                    i * MFC_1K_NUM_BLOCK_PER_SECTOR + j,
                    mfc1k->blocks[i][j][0], mfc1k->blocks[i][j][1],
                    mfc1k->blocks[i][j][2], mfc1k->blocks[i][j][3],
                    mfc1k->blocks[i][j][4], mfc1k->blocks[i][j][5],
                    mfc1k->blocks[i][j][6], mfc1k->blocks[i][j][7],
                    mfc1k->blocks[i][j][8], mfc1k->blocks[i][j][9],
                    mfc1k->blocks[i][j][10], mfc1k->blocks[i][j][11],
                    mfc1k->blocks[i][j][12], mfc1k->blocks[i][j][13],
                    mfc1k->blocks[i][j][14], mfc1k->blocks[i][j][15]);
        }
    }

    appendf(&buf, &len, &cap, "Failed authentication attempts: 0\n");

    return buf;
}

RfidxStatus mfc1k_generate(Mfc1kData *mfc1k, MfcMetadataHeader *header) {
    // Re-initialize the memory space
    memset(mfc1k, 0, sizeof(Mfc1kData));
    memset(header, 0, sizeof(MfcMetadataHeader));

    // Generate UID
    mfc_randomize_uid(mfc1k->blocks[0][0]);

    return RFIDX_OK;
}

RfidxStatus mfc1k_wipe(Mfc1kData* mfc1k) {
    // Reset all sectors
    for (int i = 0; i < MFC_1K_NUM_SECTOR; i++) {
        for (int j = 0; j < MFC_1K_NUM_BLOCK_PER_SECTOR - 1; j++) {
            if (i == 0 && j == 0) {
                // Preserve the manufacturer block (sector 0, block 0)
                continue;
            }
            memset(mfc1k->structure.sector[i].data_block[j].data, 0, MFC_1K_BLOCK_SIZE);
        }

        // Reset the keys and access bits in the sector trailer
        memset(mfc1k->structure.sector[i].sector_trailer.key_a, 0xFF, 6);
        memset(mfc1k->structure.sector[i].sector_trailer.key_b, 0xFF, 6);
        mfc1k->structure.sector[i].sector_trailer.access_bits[0] = 0xFF;
        mfc1k->structure.sector[i].sector_trailer.access_bits[1] = 0x07;
        mfc1k->structure.sector[i].sector_trailer.access_bits[2] = 0x80;
        mfc1k->structure.sector[i].sector_trailer.user_data = 0x69;
    }

    return RFIDX_OK;
}

RfidxStatus mfc1k_transform_data(
    Mfc1kData **mfc1k,
    MfcMetadataHeader **header,
    const TransformCommand command
) {
    switch (command) {
        case TRANSFORM_NONE:
            return RFIDX_OK;
        case TRANSFORM_WIPE:
            return mfc1k_wipe(*mfc1k);
        case TRANSFORM_GENERATE:
            *mfc1k = malloc(sizeof(Mfc1kData));
            if (!*mfc1k) return RFIDX_MEMORY_ERROR;

            *header = malloc(sizeof(MfcMetadataHeader));
            if (!*header) {
                free(*mfc1k);
                return RFIDX_MEMORY_ERROR;
            }

            return mfc1k_generate(*mfc1k, *header);
        case TRANSFORM_RANDOMIZE_UID:
            return mfc_randomize_uid((*mfc1k)->blocks[0][0]);
        default:
            return RFIDX_UNKNOWN_ENUM_ERROR;
    }
}
