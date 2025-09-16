/*
 * librfidx - Universal RFID Tag Format Parser and Converter
 *
 * Copyright (c) 2025. Firefox2100
 *
 * This software is released under the MIT License.
 * SPDX-License-Identifier: MIT
 */

#ifndef LIBRFIDX_MIFARE_CLASSIC_H
#define LIBRFIDX_MIFARE_CLASSIC_H

#include <stdint.h>
#include "librfidx/common.h"
#include "librfidx/mifare/mifare_common.h"

#define MFC_BLOCK_SIZE 16

#pragma pack(push, 1)
/**
 * @brief Mifare Classic family manufacturer data with 4-bytes NUID
 *
 * These bytes are read only after a tag is made
 */
typedef struct {
    uint8_t nuid[4];                /**< NUID, 3 bytes */
    uint8_t manufacturer_data[12];  /**< Manufacturer data, 12 bytes */
} MfcManufacturerData4B;
#pragma pack(pop)

#pragma pack(push, 1)
/**
 * @brief Mifare Classic family manufacturer data with 7-bytes UID
 *
 * These bytes are read only after a tag is made
 */
typedef struct {
    uint8_t uid0[7];                /**< UID, 7 bytes */
    uint8_t manufacturer_data[9];   /**< Manufacturer data, 9 bytes */
} MfcManufacturerData7B;
#pragma pack(pop)

#pragma pack(push, 1)
/**
 * @brief Mifare Classic data block
 *
 * This data structure corresponds to 16 bytes block in Mifare Classic,
 * that is not at the end of a sector (which is used to store keys). There
 * are two ways of accessing a block: as a normal block (16 bytes of storage),
 * or as a value block with stronger validation, parity and has additional
 * commands like value increment and decrement.
 *
 * A value block can still be accessed as a normal data block, but a data
 * block may only be accessed as a value block if it follows certain data
 * structure.
 */
typedef union {
    uint8_t data[MFC_BLOCK_SIZE];       /**< Raw data bytes */
    struct {
        int32_t value;                  /**< 4 bytes of signed value */
        int32_t n_value;                /**< Bit-wise inverted value */
        int32_t value_copy;             /**< A copy of the value */
        uint8_t addr;                   /**< Storage address of the block */
        uint8_t n_addr;                 /**< Bit-wise inverted address */
        uint8_t addr_copy;              /**< A copy of the address */
        uint8_t n_addr_copy;            /**< A copy of the inverted address */
    } value;                            /**< Access the block in data mode */
} MfcDataBlock;
#pragma pack(pop)

#pragma pack(push, 1)
/**
 * @brief Mifare Classic sector trailer block
 *
 * This data structure corresponds to 16 bytes block at the end of a Mifare
 * Classic sector, which stores the keys and access bits of the sector.
 */
typedef struct {
    uint8_t key_a[6];                   /**< Key A */
    uint8_t access_bits[3];             /**< Access bits */
    uint8_t user_data;                  /**< One byte not used for access control and can store user data */
    uint8_t key_b[6];                   /**< Key B */
} MfcSectorTrailer;
#pragma pack(pop)

/**
 * @brief Mifare Classic access bits
 *
 * This is the three access bits for one block, not the three bytes data.
 * It is used as a way to pass the access bits between functions.
 */
typedef struct {
    uint8_t c1;
    uint8_t c2;
    uint8_t c3;
} MfcAccessBits;

#pragma pack(push, 1)
typedef struct {
    MfcDataBlock data_block[3];
    MfcSectorTrailer sector_trailer;
} Mfc4BlockSector;
#pragma pack(pop)

/**
 * @brief Metadata header for Mifare Classic family
 *
 * These data describes the tag, and are not part of the main
 * memory structure. They are gathered from the tag using
 * ISO/IEC 14443-3 commands.
 * The struct is not packed, because this data is not present in
 * the binary dumps, and is only used in JSON and NFC formats.
 */
typedef struct {
    uint8_t uid[7];             /**< UID, up to 7 bytes. If the tag uses 4-bytes NUID, null terminate it.*/
    uint8_t atqa[2];            /**< ATQA response */
    uint8_t sak;                /**< SAK response */
} MfcMetadataHeader;

/**
 * @brief Get the access bits for a specific block in a sector trailer
 *
 * Mifare Classic sectors have 4 blocks, the last of which is the sector trailer
 * that contains the access bits for all 4 blocks. This function extracts the
 * access bits for a specific block from the sector trailer.
 * @param trailer Pointer to the sector trailer containing the access bits.
 * @param block The block number (0-3) within the sector to get the access bits for.
 * @return MfcAccessBits structure containing the access bits for the specified block.
 */
MfcAccessBits mfc_get_access_bits_for_block(const MfcSectorTrailer *trailer, uint8_t block);

RfidxStatus mfc_set_access_bits_for_block(MfcSectorTrailer *trailer, uint8_t block, MfcAccessBits access_bits);
RfidxStatus mfc_validate_access_bits(const MfcAccessBits *access_bits);

/**
 * @brief Validate the manufacturer data of a Mifare Classic tag
 *
 * Mifare Classic tags may have either 4-byte NUID or 7-byte UID. This function checks
 * the manufacturer data structure and validates the UID/NUID and BCC bytes for validity.
 * @param manufacturer_data Pointer to a 16-byte buffer containing the manufacturer data to validate.
 * @return RfidxStatus indicating success or failure of the validation.
 */
RfidxStatus mfc_validate_manufacturer_data(const uint8_t *manufacturer_data);

/**
 * @brief Randomize the UID of a Mifare Classic tag
 *
 * Mifare Classic tags may have either 4-byte NUID or 7-byte UID. This function randomizes
 * the UID/NUID while ensuring that the BCC bytes are correctly calculated.
 * @param manufacturer_data Pointer to a 16-byte buffer containing the manufacturer data to randomize.
 * @return RfidxStatus indicating success or failure of the randomization.
 */
RfidxStatus mfc_randomize_uid(const uint8_t *manufacturer_data);

_Static_assert(sizeof(MfcManufacturerData4B) == 16, "Mifare Classic manufacturer data size mismatch");
_Static_assert(sizeof(MfcManufacturerData7B) == 16, "Mifare Classic manufacturer data size mismatch");
_Static_assert(sizeof(MfcDataBlock) == MFC_BLOCK_SIZE, "Mifare Classic 1K block size mismatch");
_Static_assert(sizeof(MfcSectorTrailer) == MFC_BLOCK_SIZE, "Mifare Classic 1K sector trailer size mismatch");
_Static_assert(sizeof(Mfc4BlockSector) == (MFC_BLOCK_SIZE * 4), "Mifare Classic 1K sector size mismatch");

#endif //LIBRFIDX_MIFARE_CLASSIC_H
