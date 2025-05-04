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
}Ntag21xConfiguration;
#pragma pack(pop)

#endif //LIBRFIDX_NTAG21X_H
