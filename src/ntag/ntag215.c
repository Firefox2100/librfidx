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
#include <stdint.h>
#include <string.h>
#include <cJSON.h>
#include <ctype.h>
#include "librfidx/ntag/ntag215.h"

RfidxStatus ntag215_load_from_binary(const char *filename, Ntag215Data *ntag215, Ntag21xMetadataHeader *header) {
    FILE *file = fopen(filename, "rb");

    // Open the file
    if (!file) {
        return RFIDX_BINARY_FILE_IO_ERROR;
    }

    // Check the file size
    if (fseek(file, 0, SEEK_END) != 0) {
        fclose(file);
        return RFIDX_BINARY_FILE_IO_ERROR;
    }
    const long filesize = ftell(file);
    if (filesize == -1L) {
        fclose(file);
        return RFIDX_BINARY_FILE_IO_ERROR;
    }

    // Rewind
    if (fseek(file, 0, SEEK_SET) != 0) {
        fclose(file);
        return RFIDX_BINARY_FILE_IO_ERROR;
    }

    if (filesize == sizeof(Ntag215Data)) {
        // Contain only the dump data
        if (!fread(ntag215, sizeof(Ntag215Data), 1, file)) {
            fclose(file);
            return RFIDX_BINARY_FILE_IO_ERROR;
        }
    } else if (filesize == sizeof(Ntag215Data) + sizeof(Ntag21xMetadataHeader)) {
        // Contain both the dump and header, header first
        if (!fread(header, sizeof(Ntag21xMetadataHeader), 1, file)) {
            fclose(file);
            return RFIDX_BINARY_FILE_IO_ERROR;
        }

        if (fread(ntag215, sizeof(Ntag215Data), 1, file) != 1) {
            fclose(file);
            return RFIDX_BINARY_FILE_IO_ERROR;
        }
    } else {
        fclose(file);
        return RFIDX_BINARY_FILE_SIZE_ERROR;
    }

    fclose(file);
    return RFIDX_OK;
}

RfidxStatus ntag215_save_to_binary(const char *filename, const Ntag215Data *ntag215, const Ntag21xMetadataHeader *header) {
    FILE *file = fopen(filename, "wb");

    if (!file) {
        return RFIDX_BINARY_FILE_IO_ERROR;
    }

    // If header is not NULL or 0s, write it to the file first
    const uint8_t empty_header[sizeof(Ntag21xMetadataHeader)] = {0};
    if (header && memcmp(header, empty_header, sizeof(Ntag21xMetadataHeader)) != 0) {
        if (fwrite(header, sizeof(Ntag21xMetadataHeader), 1, file) != 1) {
            fclose(file);
            return RFIDX_BINARY_FILE_IO_ERROR;
        }
    }

    if (fwrite(ntag215, sizeof(Ntag215Data), 1, file) != 1) {
        fclose(file);
        return RFIDX_BINARY_FILE_IO_ERROR;
    }

    fclose(file);
    return RFIDX_OK;
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
        snprintf(idx, sizeof(idx), "%d", i);
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

    cJSON *card_data = cJSON_GetObjectItem(root, "Card");
    if (!card_data) {
        cJSON_Delete(root);
        return RFIDX_JSON_PARSE_ERROR;
    }
    const RfidxStatus header_load_status = ntag215_parse_header_from_json(card_data, header);
    if (header_load_status != RFIDX_OK) {
        cJSON_Delete(root);
        return header_load_status;
    }

    cJSON *blocks_data = cJSON_GetObjectItem(root, "blocks");
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

RfidxStatus ntag215_load_from_json(const char *filename, Ntag215Data *ntag215, Ntag21xMetadataHeader *header) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        return RFIDX_JSON_FILE_IO_ERROR;
    }

    fseek(file, 0, SEEK_END);
    const long file_length = ftell(file);
    rewind(file);

    char *buffer = malloc(file_length + 1);
    if (!buffer) {
        fclose(file);
        return RFIDX_JSON_FILE_IO_ERROR;
    }

    if (fread(buffer, 1, file_length, file) != (size_t)file_length) {
        fclose(file);
        free(buffer);
        return RFIDX_JSON_FILE_IO_ERROR;
    }

    buffer[file_length] = '\0';
    fclose(file);

    const RfidxStatus parsing_status = ntag215_parse_json(buffer, ntag215, header);
    if (parsing_status != RFIDX_OK) {
        free(buffer);
        return parsing_status;
    }

    free(buffer);
    return RFIDX_OK;
}

cJSON * ntag215_dump_header_to_json(const Ntag21xMetadataHeader *header) {
    cJSON *card_obj = cJSON_CreateObject();
    char hex[65];

    bytes_to_hex(header->version, 8, hex); hex[16] = '\0';
    cJSON_AddStringToObject(card_obj, "Version", hex);

    bytes_to_hex(header->tbo0, 2, hex); hex[4] = '\0';
    cJSON_AddStringToObject(card_obj, "TBO_0", hex);

    bytes_to_hex(&header->tbo1, 1, hex); hex[2] = '\0';
    cJSON_AddStringToObject(card_obj, "TBO_1", hex);

    bytes_to_hex(header->signature, 32, hex); hex[64] = '\0';
    cJSON_AddStringToObject(card_obj, "Signature", hex);

    bytes_to_hex(header->counter0, 3, hex); hex[6] = '\0';
    cJSON_AddStringToObject(card_obj, "Counter0", hex);
    bytes_to_hex(&header->tearing0, 1, hex); hex[2] = '\0';
    cJSON_AddStringToObject(card_obj, "Tearing0", hex);

    bytes_to_hex(header->counter1, 3, hex); hex[6] = '\0';
    cJSON_AddStringToObject(card_obj, "Counter1", hex);
    bytes_to_hex(&header->tearing1, 1, hex); hex[2] = '\0';
    cJSON_AddStringToObject(card_obj, "Tearing1", hex);

    bytes_to_hex(header->counter2, 3, hex); hex[6] = '\0';
    cJSON_AddStringToObject(card_obj, "Counter2", hex);
    bytes_to_hex(&header->tearing2, 1, hex); hex[2] = '\0';
    cJSON_AddStringToObject(card_obj, "Tearing2", hex);

    return card_obj;
}

cJSON * ntag215_dump_data_to_json(const Ntag215Data *ntag215) {
    cJSON *blocks_obj = cJSON_CreateObject();
    char hex[9];

    for (int i = 0; i < NTAG215_NUM_USER_PAGES; i++) {
        bytes_to_hex(ntag215->pages[i], 4, hex);
        hex[8] = '\0';
        char idx[8];
        snprintf(idx, sizeof(idx), "%d", i);
        cJSON_AddStringToObject(blocks_obj, idx, hex);
    }

    return RFIDX_OK;
}

char* ntag215_serialize_json(const Ntag215Data *ntag215, const Ntag21xMetadataHeader *header) {
    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "Created", "proxmark3");
    cJSON_AddStringToObject(root, "FileType", "mfu");

    cJSON_AddItemToObject(root, "Card", ntag215_dump_header_to_json(header));
    cJSON_AddItemToObject(root, "blocks", ntag215_dump_data_to_json(ntag215));

    char *output = cJSON_Print(root);
    cJSON_Delete(root);

    return output;
}

RfidxStatus ntag215_save_to_json(const char *filename, const Ntag215Data *ntag215, const Ntag21xMetadataHeader *header) {
    char *json_str = ntag215_serialize_json(ntag215, header);
    if (!json_str) {
        return RFIDX_JSON_PARSE_ERROR;
    }

    FILE *file = fopen(filename, "w");
    if (!file) {
        free(json_str);
        return RFIDX_JSON_FILE_IO_ERROR;
    }

    if (fputs(json_str, file) == EOF) {
        fclose(file);
        return RFIDX_JSON_FILE_IO_ERROR;
    }

    fclose(file);
    free(json_str);
    return RFIDX_OK;
}

RfidxStatus ntag215_parse_nfc(const char *nfc_str, Ntag215Data *ntag215, Ntag21xMetadataHeader *header) {
    const char* start = nfc_str;
    const char* end;

    while ((end = strchr(start, '\n')) != NULL) {
        const size_t line_length = end - start;
        char* line = malloc(line_length + 1);
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
                    uint32_t c = (uint32_t)strtoul(val, &endptr, 10);
                    if (val == endptr) {
                        free(line);
                        return RFIDX_NFC_PARSE_ERROR;
                    }
                    header->counter0[0] = (c >> 16) & 0xFF;
                    header->counter0[1] = (c >> 8) & 0xFF;
                    header->counter0[2] = c & 0xFF;
                } else if (strncmp(key, "Tearing 0", 9) == 0) {
                    header->tearing0 = (uint8_t)strtol(val, NULL, 16);
                } else if (strncmp(key, "Counter 1", 9) == 0) {
                    char *endptr;
                    uint32_t c = (uint32_t)strtoul(val, &endptr, 10);
                    if (val == endptr) {
                        free(line);
                        return RFIDX_NFC_PARSE_ERROR;
                    }
                    header->counter1[0] = (c >> 16) & 0xFF;
                    header->counter1[1] = (c >> 8) & 0xFF;
                    header->counter1[2] = c & 0xFF;
                } else if (strncmp(key, "Tearing 1", 9) == 0) {
                    header->tearing1 = (uint8_t)strtol(val, NULL, 16);
                } else if (strncmp(key, "Counter 2", 9) == 0) {
                    char *endptr;
                    uint32_t c = (uint32_t)strtoul(val, &endptr, 10);
                    if (val == endptr) {
                        free(line);
                        return RFIDX_NFC_PARSE_ERROR;
                    }
                    header->counter2[0] = (c >> 16) & 0xFF;
                    header->counter2[1] = (c >> 8) & 0xFF;
                    header->counter2[2] = c & 0xFF;
                } else if (strncmp(key, "Tearing 2", 9) == 0) {
                    header->tearing2 = (uint8_t)strtol(val, NULL, 16);
                } else if (strncmp(key, "Pages total", 11) == 0) {
                    header->memory_max = (uint8_t)strtol(val, NULL, 10) - 1;
                } else if (strncmp(key, "Page ", 5) == 0) {
                    char *endptr;
                    uint32_t page = strtoul(key + 5, &endptr, 10);
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

RfidxStatus ntag215_load_from_nfc(const char *filename, Ntag215Data *ntag215, Ntag21xMetadataHeader *header) {
    FILE* file = fopen(filename, "r");
    if (!file) {
        return RFIDX_NFC_FILE_IO_ERROR;
    }

    fseek(file, 0, SEEK_END);
    const long file_length = ftell(file);
    rewind(file);

    char *buffer = malloc(file_length + 1);
    if (!buffer) {
        fclose(file);
        return RFIDX_NFC_FILE_IO_ERROR;
    }

    if (fread(buffer, 1, file_length, file) != (size_t)file_length) {
        fclose(file);
        free(buffer);
        return RFIDX_NFC_FILE_IO_ERROR;
    }

    buffer[file_length] = '\0';
    fclose(file);

    const RfidxStatus parsing_status = ntag215_parse_nfc(buffer, ntag215, header);
    free(buffer);
    return parsing_status;
}
