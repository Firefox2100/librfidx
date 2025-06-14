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

#include "librfidx/ntag/ntag215_core.h"

#define RFIDX_AMIIBO_KEY_IO_ERROR 0xFFFF0200U
#define RFIDX_AMIIBO_HMAC_VALIDATION_ERROR 0xFFFF0201U

#pragma pack(push, 1)
/**
 * @brief Single dumped key structure
 *
 * This format is used for they keys dumped directly from console, or
 * the ones being used in other common projects like amiitools or proxmark 3.
 */
typedef struct {
    uint8_t hmacKey[16];        /**< 16 bytes HMAC key */
    char typeString[14];        /**< 14 bytes type string, e.g. "unfixed info" */
    uint8_t rfu;                /**< Reserved for future use */
    uint8_t magicBytesSize;     /**< Size of the magic bytes, either 14 or 16 */
    uint8_t magicBytes[16];     /**< 16 bytes magic bytes, used for key generation */
    uint8_t xorTable[32];       /**< 32 bytes XOR table, used for key generation */
} DumpedKeySingle;
#pragma pack(pop)

#pragma pack(push, 1)
/**
 * @brief Derived key structure
 *
 * This structure contains the derived keys used for encryption and HMAC.
 * It is derived from the dumped key and Amiibo data.
 */
typedef struct {
    const uint8_t aesKey[16];   /**< AES key used for cypher */
    const uint8_t aesIV[16];    /**< AES initialization vector */
    const uint8_t hmacKey[16];  /**< HMAC key used for signature */
} DerivedKey;
#pragma pack(pop)

#pragma pack(push, 1)
/**
 * @brief Combined dumped keys structure
 *
 * This structure contains two DumpedKeySingle structures, one for the data key
 * and one for the tag key. Combined they become the key_retail usually required
 * by similar tools.
 */
typedef struct {
    DumpedKeySingle data; /**< Data key */
    DumpedKeySingle tag; /**< Tag key */
} DumpedKeys;
#pragma pack(pop)

#pragma pack(push, 1)
/**
 * @brief Amiibo tag configuration
 *
 * This part contains the configuration related to Amiibo tag itself, such as read/write
 * records, and short name. All Amiibo use the same format. AES encrypted.
 */
typedef struct {
    uint8_t settings[2];        /**< Settings bits */
    uint8_t crc_counter[2];     /**< CRC counter, incremented when data updates */
    uint8_t init_date[2];       /**< Initialization date */
    uint8_t write_date[2];      /**< Last write date */
    uint8_t crc[4];             /**< CRC32 checksum of the tag data */
    uint8_t nickname[20];       /**< Short name of the Amiibo, 20 bytes maximum */
} AmiiboTagConfig;
#pragma pack(pop)

#pragma pack(push, 1)
/**
 * @brief Model information for Amiibo
 *
 * This structure contains the 12 bytes data for model information, representing
 * what character this amiibo is. In online data tables it's usually divided into
 * 4 + 4 = 8 bytes, with the last 4 bytes unknown and not used in tables.
 */
typedef union {
    uint8_t bytes[12];
    struct {
        uint8_t character_id[2];    /**< ID of the character */
        uint8_t variation;          /**< Variation of the character, e.g. different color or pose */
        uint8_t form;               /**< Form of the amiibo, e.g. card or figure */
        uint8_t amiibo_id[2];       /**< ID of this Amiibo model */
        uint8_t set;                /**< Which set this Amiibo is released under */
        uint8_t fixed_02;           /**< Fixed byte 0x02 */
        uint8_t unknown_4[4];       /**< Unknown bytes, no correlation has been found yet */
    };
} AmiiboModelInfo;
#pragma pack(pop)

#pragma pack(push, 1)
/**
 * @brief Application data for Amiibo
 *
 * This structure contains the application data for Amiibo, which includes
 * owner information, what game is using it, and the data written to it by the game.
 * AES encrypted and HMAC signed.
 */
typedef union {
    uint8_t bytes[360];
    struct {
        uint8_t owner_mii[96];      /**< Mii character data for the owner, somehow compressed or encoded */
        uint8_t title_id[8];        /**< Title ID of the game that wrote to this Amiibo */
        uint8_t write_count[2];     /**< Write count, incremented when data updates */
        uint8_t app_id[2];          /**< Application ID */
        uint8_t unknown_4[4];       /**< Unknown bytes, no correlation has been found yet */
        uint8_t hash[32];           /**< Internal hash, managed by the game */
        uint8_t app_data[216];      /**< Application data written by the game, 216 bytes maximum */
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

/**
 * @brief Amiibo data union overlay
 *
 * This structure contains the raw data, the bytes and the structured data
 * of the Amiibo tag. It is used to load and save the tag data in different
 * formats.
 */
typedef union {
    Ntag215Data ntag215;        /**< Memory by NTAG215 data */
    AmiiboStructure amiibo;     /**< Memory by Amiibo structure */
} AmiiboData;

/**
 * @brief Derive keys from dumped key and Amiibo data
 *
 * Amiibo keys are derived from the key generation salt and the keys extracted
 * from the console. This function takes both input, and derive the key for use
 * with this specific Amiibo.
 * @param input_key The dumped key to derive from
 * @param amiibo_data The Amiibo data to derive the key for
 * @param derived_key The derived key to fill with the result
 * @return RFIDX_OK on success, or an error code on failure
 */
RFIDX_EXPORT RfidxStatus amiibo_derive_key(
    const DumpedKeySingle *input_key,
    const AmiiboData *amiibo_data,
    DerivedKey *derived_key
);

/**
 * @brief Run AES cipher on Amiibo data
 *
 * Amiibo data is encrypted using AES-128 in CTR mode. This function
 * runs the cypher on the Amiibo data, handling both encryption and decryption.
 * @param data_key The derived data key to use for encryption/decryption
 * @param amiibo_data The Amiibo data to encrypt/decrypt
 * @return RFIDX_OK on success, or an error code on failure
 */
RFIDX_EXPORT RfidxStatus amiibo_cipher(const DerivedKey *data_key, AmiiboData* amiibo_data);

/**
 * @brief Generate HMAC signature for Amiibo data
 *
 * Amiibo has 2 signature, generated from 2 different HMAC signing keys, and used to sign
 * different data. This function generates the signatures for both tag and data, filling
 * the provided buffers with the result. Can only be used on decrypted Amiibo data.
 * @param tag_key The derived tag key to use for signing the tag data
 * @param data_key The derived data key to use for signing the application data
 * @param amiibo_data The Amiibo data to sign
 * @param tag_hash The buffer to fill with the tag signature
 * @param data_hash The buffer to fill with the data signature
 * @return RFIDX_OK on success, or an error code on failure
 */
RfidxStatus amiibo_generate_signature(
    const DerivedKey *tag_key,
    const DerivedKey *data_key,
    const AmiiboData* amiibo_data,
    uint8_t *tag_hash,
    uint8_t *data_hash
);

/**
 * @brief Validate the HMAC signature of Amiibo data
 *
 * Validate existing HMAC signatures of the Amiibo data, useful for checking
 * if the dump is valid. Can only be used on decrypted Amiibo data.
 * @param tag_key The derived tag key to use for validating the tag signature
 * @param data_key The derived data key to use for validating the application data signature
 * @param amiibo_data The Amiibo data to validate
 * @return RFIDX_OK on success, or an error code on failure
 */
RFIDX_EXPORT RfidxStatus amiibo_validate_signature(
    const DerivedKey *tag_key,
    const DerivedKey *data_key,
    const AmiiboData* amiibo_data
);

/**
 * @brief Sign the payload of Amiibo data
 *
 * Utility function to generate signature and add to Amiibo buffer in-place.
 * Can only be used on decrypted Amiibo data.
 * @param tag_key The derived tag key to use for signing the tag data
 * @param data_key The derived data key to use for signing the application data
 * @param amiibo_data The Amiibo data to sign
 * @return RFIDX_OK on success, or an error code on failure
 */
RFIDX_EXPORT RfidxStatus amiibo_sign_payload(
    const DerivedKey *tag_key,
    const DerivedKey *data_key,
    AmiiboData* amiibo_data
);

/**
 * @brief Format the Amiibo data for output
 *
 * This function reformats the control values and password, etc. for an Amiibo dump.
 * It's used to clean up the dump for simulation.
 * @param amiibo_data The Amiibo data to format
 * @param header The NTAG21x metadata header to fill with the formatted data
 * @return RFIDX_OK on success, or an error code on failure
 */
RfidxStatus amiibo_format_dump(AmiiboData* amiibo_data, Ntag21xMetadataHeader *header);

/**
 * @brief Generate a new Amiibo data structure
 *
 * This function generates a new Amiibo blank dump for a given UUID. The UUID is an 8
 * byte value that represents a specific Amiibo. Such value can be found on online databases
 * like AmiiboAPI. The result is a blank Amiibo for that character, with basic format control
 * and can be used directly in emulation or writing.
 * @param uuid The 8 byte UUID of the Amiibo to generate
 * @param amiibo_data The Amiibo data to fill with the generated data
 * @param header The NTAG21x metadata header to fill with the generated data
 * @return RFIDX_OK on success, or an error code on failure
 */
RFIDX_EXPORT RfidxStatus amiibo_generate(
    const uint8_t *uuid,
    AmiiboData *amiibo_data,
    Ntag21xMetadataHeader *header
);

/**
 * @brief Wipe the Amiibo data
 *
 * This function resets the Amiibo application data without altering the tag UID, Amiibo model
 * information, or tag configuration. It's the same as resetting an Amiibo at the console, except more
 * thorough.
 * @param amiibo_data The Amiibo data to wipe
 * @return RFIDX_OK on success, or an error code on failure
 */
RFIDX_EXPORT RfidxStatus amiibo_wipe(AmiiboData *amiibo_data);
RFIDX_EXPORT RfidxStatus amiibo_transform_data(
    AmiiboData **amiibo_data,
    Ntag21xMetadataHeader **header,
    TransformCommand command,
    const uint8_t *uuid,
    const DumpedKeys *dumped_keys
);

_Static_assert(sizeof(DumpedKeySingle) == 80, "Amiibo single key size mismatch");
_Static_assert(sizeof(DumpedKeys) == 160, "Amiibo combined key size mismatch");
_Static_assert(sizeof(AmiiboTagConfig) == 32, "Amiibo tag configuration size mismatch");
_Static_assert(sizeof(AmiiboModelInfo) == 12, "Amiibo model information size mismatch");
_Static_assert(sizeof(AmiiboApplicationData) == 360, "Amiibo application data size mismatch");
_Static_assert(sizeof(AmiiboStructure) == 540, "Amiibo data size mismatch");
_Static_assert(sizeof(AmiiboData) == 540, "Amiibo data union size mismatch");

#endif //LIBRFIDX_AMIIBO_CORE_H
