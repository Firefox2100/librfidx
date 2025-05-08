/*
 * librfidx - Universal RFID Tag Format Parser and Converter
 *
 * Copyright (c) 2025. Firefox2100
 *
 * This software is released under the MIT License.
 * SPDX-License-Identifier: MIT
 */

#ifndef LIBRFIDX_AMIIBO_CORE_H
#define LIBRFIDX_AMIIBO_CORE_H

#include "librfidx/ntag/ntag215.h"

#define RFIDX_AMIIBO_KEY_IO_ERROR -1024

#pragma pack(push, 1)
typedef struct {
    uint8_t hmacKey[16];
    char typeString[14];
    uint8_t rfu;
    uint8_t magicBytesSize;
    uint8_t magicBytes[16];
    uint8_t xorTable[32];
} DumpedKeySingle;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct {
    const uint8_t aesKey[16];
    const uint8_t aesIV[16];
    const uint8_t hmacKey[16];
} DerivedKey;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct {
    DumpedKeySingle data;
    DumpedKeySingle tag;
} DumpedKeys;
#pragma pack(pop)

#pragma pack(push, 1)
/**
 * @brief Amiibo tag configuration
 *
 * This part contains the configuration related to how NTAG215 is expected
 * to be read and written. It is shared between all Amiibo tags. AES encrypted.
 */
typedef struct {
    uint8_t settings[2];
    uint8_t crc_counter[2];
    uint8_t init_date[2];
    uint8_t write_date[2];
    uint8_t crc[4];
    uint8_t nickname[20];
} AmiiboTagConfig;
#pragma pack(pop)

#pragma pack(push, 1)
typedef union {
    uint8_t bytes[12];
    struct {
        uint8_t character_id[2];
        uint8_t variation;
        uint8_t form;
        uint8_t amiibo_id[2];
        uint8_t set;
        uint8_t fixed_02;
        uint8_t unknown_4[4];
    };
} AmiiboModelInfo;
#pragma pack(pop)

#pragma pack(push, 1)
typedef union {
    uint8_t bytes[360];
    struct {
        uint8_t owner_mii[96];
        uint8_t title_id[8];
        uint8_t write_count[2];
        uint8_t app_id[2];
        uint8_t unknown_4[4];
        uint8_t hash[32];
        uint8_t app_data[216];
    };
} AmiiboApplicationData;
#pragma pack(pop)

#pragma pack(push, 1)
/**
 * @brief Amiibo data structure
 */
typedef struct {
    Ntag21xManufacturerData manufacturer_data;      /**< Manufacturer data */
    uint8_t capability[4];                          /**< Capability container */
    uint8_t fixed_a5;                               /**< Fixed byte 0xA5 */
    uint8_t write_counter[2];                       /**< Write counter, incremented when data updates */
    uint8_t unknown_1;                              /**< Unknown byte */
    AmiiboTagConfig tag_configs;                    /**< Tag configuration data */
    uint8_t tag_hash[32];                           /**< HMAC hash from UID + model info + keygen salt */
    AmiiboModelInfo model_info;                     /**< Model information */
    uint8_t keygen_salt[32];                        /**< Key generation salt */
    uint8_t data_hash[32];                          /**< HMAC hash from tag setting + decrypted Amiibo data + tag hash + UID + keygen salt */
    AmiiboApplicationData data;                     /** Application data */
    uint8_t dynamic_lock[3];                        /**< Dynamic lock bits */
    uint8_t reserved;                               /**< Reserved byte */
    Ntag21xConfiguration configuration;             /**< Configuration data */
} AmiiboStructure;
#pragma pack(pop)

typedef union {
    Ntag215Data ntag215;
    AmiiboStructure amiibo;
} AmiiboData;

RfidxStatus amiibo_derive_key(
    const DumpedKeySingle *input_key,
    const AmiiboData *amiibo_data,
    DerivedKey *derived_key
);

RfidxStatus amiibo_cipher(const DerivedKey *data_key, AmiiboData* amiibo_data);

#endif //LIBRFIDX_AMIIBO_CORE_H
