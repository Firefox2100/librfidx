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

MfcAccessBits mfc_get_access_bits_for_block(const MfcSectorTrailer *trailer, uint8_t block);
RfidxStatus mfc_set_access_bits_for_block(MfcSectorTrailer *trailer, uint8_t block, MfcAccessBits access_bits);
RfidxStatus mfc_validate_access_bits(const MfcAccessBits *access_bits);

_Static_assert(sizeof(MfcDataBlock) == MFC_BLOCK_SIZE, "Mifare Classic 1K block size mismatch");
_Static_assert(sizeof(MfcSectorTrailer) == MFC_BLOCK_SIZE, "Mifare Classic 1K sector trailer size mismatch");
_Static_assert(sizeof(Mfc4BlockSector) == (MFC_BLOCK_SIZE * 4), "Mifare Classic 1K sector size mismatch");

#endif //LIBRFIDX_MIFARE_CLASSIC_H
