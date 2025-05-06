/*
 * librfidx - Universal RFID Tag Format Parser and Converter
 *
 * Copyright (c) 2025. Firefox2100
 *
 * This software is released under the MIT License.
 * SPDX-License-Identifier: MIT
 */

#ifndef LIBRFIDX_NTAG21X_H
#define LIBRFIDX_NTAG21X_H

#include <stdint.h>
#include "librfidx/ntag/ntag_common.h"

#define NTAG21X_PAGE_SIZE 4

#pragma pack(push, 1)
/**
 * @brief NTAG21x family manufacturer data and static lock bits
 *
 * These bytes are read only after a tag is made
 */
typedef struct {
    uint8_t uid0[3];        /**< First part of UID */
    uint8_t bcc0;           /**< Block Check Character 0 */
    uint8_t uid1[4];        /**< Second part of UID */
    uint8_t bcc1;           /**< Block Check Character 1 */
    uint8_t internal;       /**< Internal configuration byte */
    uint8_t lock[2];        /**< Lock bytes */
} Ntag21xManufacturerData;
#pragma pack(pop)

#pragma pack(push, 1)
/**
 * @brief NTAG21x family configuration data
 *
 * These bytes are read only after a tag is made
 */
typedef struct {
    uint8_t cfg0[4];        /**< Configuration page 0 */
    uint8_t cfg1[4];        /**< Configuration page 1 */
    uint8_t passwd[4];      /**< Password used to authenticate with the tag */
    uint8_t pack[2];        /**< Password Acknowledge */
    uint8_t reserved[2];    /**< Reserved bytes */
} Ntag21xConfiguration;
#pragma pack(pop)

#pragma pack(push, 1)
/**
 * @brief Metadata header for NTAG21x family
 *
 * These bytes are read only after a tag is made, and are not part of the main
 * memory structure. They are read with NTAG-specific commands. Not all readers
 * support them, so you may get away with not reading or simulating them.
 */
typedef struct {
    uint8_t version[8];         /**< Version string with vendor, product version, etc. */
    uint8_t tbo0[2];            /**< Tear Backup Object 0, anti-tearing feature */
    uint8_t tbo1;               /**< Tear Backup Object 1, continuation of TBO0 */
    uint8_t memory_max;         /**< Maximum memory page index. It's <b> 1 - memory size </b> */
    NtagSignature signature;    /**< Signature of the tag, signed with NXP private key */
    uint8_t counter0[3];        /**< Counter 0, only operable with INCR command */
    uint8_t tearing0;           /**< Tearing flag 0, part of counter anti-tearing */
    uint8_t counter1[3];        /**< Counter 1, only operable with INCR command */
    uint8_t tearing1;           /**< Tearing flag 1, part of counter anti-tearing */
    uint8_t counter2[3];        /**< Counter 2, only operable with INCR command */
    uint8_t tearing2;           /**< Tearing flag 2, part of counter anti-tearing */
} Ntag21xMetadataHeader;
#pragma pack(pop)

#endif //LIBRFIDX_NTAG21X_H
