/*
 * librfidx - Universal RFID Tag Format Parser and Converter
 *
 * Copyright (c) 2025. Firefox2100
 *
 * This software is released under the MIT License.
 * SPDX-License-Identifier: MIT
 */

#ifndef LIBRFIDX_NTAG215_H
#define LIBRFIDX_NTAG215_H

#include <stdint.h>
#include "librfidx/common.h"
#include "librfidx/ntag/ntag21x.h"

#define NTAG215_PAGE_SIZE NTAG21X_PAGE_SIZE
#define NTAG215_NUM_PAGES 135
#define NTAG215_NUM_USER_PAGES 126
#define NTAG215_TOTAL_BYTES (NTAG215_PAGE_SIZE * NTAG215_NUM_PAGES)

/**
 * @brief NTAG215 raw data structure
 *
 * Raw data structure: 135 pages of 4 bytes each
 */
typedef uint8_t Ntag215Raw[NTAG215_NUM_PAGES][NTAG215_PAGE_SIZE];

#pragma pack(push, 1)
/**
 * @brief NTAG215 family manufacturer data and static lock bits
 *
 * These bytes are read only after a tag is made
 */
typedef struct {
    Ntag21xManufacturerData manufacturer_data;                          /**< Manufacturer data */
    uint8_t capability[4];                                              /**< Capability container */
    uint8_t user_memory[NTAG215_NUM_USER_PAGES][NTAG21X_PAGE_SIZE];     /** <User usable memory */
    uint8_t dynamic_lock[3];                                            /**< Dynamic lock bits */
    uint8_t reserved;                                                   /**< Reserved byte */
    Ntag21xConfiguration configuration;                                 /**< Configuration data */
} Ntag215Structure;
#pragma pack(pop)

typedef union {
    Ntag215Raw pages;
    uint8_t bytes[NTAG215_TOTAL_BYTES];
    Ntag215Structure structure;
} Ntag215Data;

/**
 * @brief Load NTAG215 data from a binary file
 *
 * Provided a path to binary file, a NTAG215Data buffer and a signature buffer,
 * this function will load the data from the file into the buffers. If the file
 * contains the signature, it will also be loaded. Returns error if the file
 * can't be opened, or the size is wrong.
 * @param filename Path to the binary file.
 * @param ntag215 Pointer to the NTAG215Data buffer to load the data into.
 * @param header: Pointer to the Ntag21xProxmarkHeader buffer to load Proxmark 3 metadata into.
 * @return Status code
 */
RfidxStatus ntag215_load_from_binary(const char *filename, Ntag215Data *ntag215, Ntag21xProxmarkHeader *header);

/**
 * @brief Saves NTAG215 data to a binary file
 *
 * Provided a path to save the binary file, a NTAG215Data buffer and a signature buffer,
 * this function will save the data to the file system. If the signature pointer is not null,
 * and the buffer is not full of 0x00, it will also be saved. Returns error if the file
 * writing fails.
 * @param filename Path to the binary file.
 * @param ntag215 Pointer to the NTAG215Data data.
 * @param header: Pointer to the Ntag21xProxmarkHeader buffer to save Proxmark 3 metadata into.
 * @return Status code
 */
RfidxStatus ntag215_save_to_binary(const char *filename, const Ntag215Data *ntag215, const Ntag21xProxmarkHeader *header);

RfidxStatus ntag215_load_from_eml(char *filename, Ntag215Data *ntag215, Ntag21xProxmarkHeader *header);
RfidxStatus ntag215_save_to_eml(char *filename, Ntag215Data *ntag215, Ntag21xProxmarkHeader *header);
RfidxStatus ntag215_load_from_json(char *filename, Ntag215Data *ntag215, Ntag21xProxmarkHeader *header);
RfidxStatus ntag215_save_to_json(char *filename, Ntag215Data *ntag215, Ntag21xProxmarkHeader *header);
RfidxStatus ntag215_load_from_nfc(char *filename, Ntag215Data *ntag215, Ntag21xProxmarkHeader *header);
RfidxStatus ntag215_save_to_nfc(char *filename, Ntag215Data *ntag215, Ntag21xProxmarkHeader *header);

#endif //LIBRFIDX_NTAG215_H
