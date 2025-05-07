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
 * @brief NTAG215 data structure
 */
typedef struct {
    Ntag21xManufacturerData manufacturer_data; /**< Manufacturer data */
    uint8_t capability[4]; /**< Capability container */
    uint8_t user_memory[NTAG215_NUM_USER_PAGES][NTAG21X_PAGE_SIZE]; /** <User usable memory */
    uint8_t dynamic_lock[3]; /**< Dynamic lock bits */
    uint8_t reserved; /**< Reserved byte */
    Ntag21xConfiguration configuration; /**< Configuration data */
} Ntag215Structure;
#pragma pack(pop)

/**
 * @brief NTAG215 data union overlay
 *
 * This structure contains the raw data, the bytes and the structured data
 * of the NTAG215 tag. It is used to load and save the tag data in different
 * formats.
 */
typedef union {
    Ntag215Raw pages; /**< Memory by page, 135 * 4 bytes */
    uint8_t bytes[NTAG215_TOTAL_BYTES]; /**< Memory by byte, 540 bytes */
    Ntag215Structure structure; /**< Memory by structure */
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
RfidxStatus ntag215_load_from_binary(
    const char *filename,
    Ntag215Data *ntag215,
    Ntag21xMetadataHeader *header
);

/**
 * @brief Serialize NTAG215 data and header to binary
 *
 * Provided a NTAG215Data buffer and a signature buffer, this function
 * processes the data and header into a binary format.
 * @param ntag215 Pointer to the NTAG215Data data.
 * @param header: Pointer to the Ntag21xProxmarkHeader buffer to save Proxmark 3 metadata into.
 * @return Binary data
 */
uint8_t *ntag215_serialize_binary(
    const Ntag215Data *ntag215,
    const Ntag21xMetadataHeader *header
);

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
RfidxStatus ntag215_save_to_binary(
    const char *filename,
    const Ntag215Data *ntag215,
    const Ntag21xMetadataHeader *header
);

RfidxStatus ntag215_load_from_eml(
    char *filename,
    Ntag215Data *ntag215,
    Ntag21xMetadataHeader *header
);
RfidxStatus ntag215_save_to_eml(
    char *filename,
    Ntag215Data *ntag215,
    Ntag21xMetadataHeader *header
);

/**
 * @brief Parse a JSON string into NTAG215 data and header
 *
 * Provided a JSON string, a NTAG215Data buffer and a signature buffer, this function
 * processes the JSON string and loads the data into the buffers. If the JSON string
 * is malformed, or the data is not in the expected format, it will return an error.
 * @param json_str The JSON string to parse.
 * @param ntag215 Pointer to the NTAG215Data data.
 * @param header: Pointer to the Ntag21xProxmarkHeader buffer to save Proxmark 3 metadata into.
 * @return Status code
 */
RfidxStatus ntag215_parse_json(
    const char *json_str,
    Ntag215Data *ntag215,
    Ntag21xMetadataHeader *header
);

/**
 * @brief Load NTAG215 data from a JSON file
 *
 * Provided a path to JSON file, a NTAG215Data buffer and a signature buffer,
 * this function will load the data from the file into the buffers. If the file
 * contains the signature, it will also be loaded. Returns error if the file
 * can't be opened, or the size is wrong.
 * @param filename Path to the JSON file.
 * @param ntag215 Pointer to the NTAG215Data data.
 * @param header: Pointer to the Ntag21xProxmarkHeader buffer to save Proxmark 3 metadata into.
 * @return Status code
 */
RfidxStatus ntag215_load_from_json(
    const char *filename,
    Ntag215Data *ntag215,
    Ntag21xMetadataHeader *header
);

/**
 * @brief Serialize NTAG215 data and header to JSON string
 *
 * Provided a NTAG215Data buffer and a signature buffer, this function
 * processes the data and header into a JSON string.
 * @param ntag215 Pointer to the NTAG215Data data.
 * @param header: Pointer to the Ntag21xProxmarkHeader buffer to save Proxmark 3 metadata into.
 * @return JSON string
 */
char *ntag215_serialize_json(
    const Ntag215Data *ntag215,
    const Ntag21xMetadataHeader *header
);

/**
 * @brief Save NTAG215 data and header to a JSON file
 *
 * Provided a path to save the JSON file, a NTAG215Data buffer and a signature buffer,
 * this function will save the data to the file system. If the signature pointer is not null,
 * and the buffer is not full of 0x00, it will also be saved. Returns error if the file
 * writing fails.
 * @param filename Path to the JSON file.
 * @param ntag215 Pointer to the NTAG215Data data.
 * @param header: Pointer to the Ntag21xProxmarkHeader buffer to save Proxmark 3 metadata into.
 * @return Status code
 */
RfidxStatus ntag215_save_to_json(
    const char *filename,
    const Ntag215Data *ntag215,
    const Ntag21xMetadataHeader *header
);

/**
 * @brief Parse a NFC string into NTAG215 data and header
 *
 * Provided a NFC string, a NTAG215Data buffer and a signature buffer, this function
 * processes the NFC string and loads the data into the buffers. If the NFC string
 * is malformed, or the data is not in the expected format, it will return an error.
 * @param nfc_str The NFC string to parse.
 * @param ntag215 Pointer to the NTAG215Data data.
 * @param header: Pointer to the Ntag21xProxmarkHeader buffer to save Proxmark 3 metadata into.
 * @return Status code
 */
RfidxStatus ntag215_parse_nfc(
    const char *nfc_str,
    Ntag215Data *ntag215,
    Ntag21xMetadataHeader *header
);

/**
 * @brief Load NTAG215 data from a NFC file
 *
 * Provided a path to NFC file, a NTAG215Data buffer and a signature buffer,
 * this function will load the data from the file into the buffers. If the file
 * contains the signature, it will also be loaded. Returns error if the file
 * can't be opened, or the size is wrong.
 * @param filename Path to the NFC file.
 * @param ntag215 Pointer to the NTAG215Data data.
 * @param header: Pointer to the Ntag21xProxmarkHeader buffer to save Proxmark 3 metadata into.
 * @return Status code
 */
RfidxStatus ntag215_load_from_nfc(
    const char *filename,
    Ntag215Data *ntag215,
    Ntag21xMetadataHeader *header
);

/**
 * @brief Serialize NTAG215 data and header to NFC string
 *
 * Provided a NTAG215Data buffer and a signature buffer, this function
 * processes the data and header into a NFC string.
 * @param ntag215 Pointer to the NTAG215Data data.
 * @param header: Pointer to the Ntag21xProxmarkHeader buffer to save Proxmark 3 metadata into.
 * @return NFC string
 */
char *ntag215_serialize_nfc(
    const Ntag215Data *ntag215,
    const Ntag21xMetadataHeader *header
);

/**
 * @brief Save NTAG215 data and header to a NFC file
 *
 * Provided a path to save the NFC file, a NTAG215Data buffer and a signature buffer,
 * this function will save the data to the file system. If the signature pointer is not null,
 * and the buffer is not full of 0x00, it will also be saved. Returns error if the file
 * writing fails.
 * @param filename Path to the NFC file.
 * @param ntag215 Pointer to the NTAG215Data data.
 * @param header: Pointer to the Ntag21xProxmarkHeader buffer to save Proxmark 3 metadata into.
 * @return Status code
 */
RfidxStatus ntag215_save_to_nfc(
    const char *filename,
    const Ntag215Data *ntag215,
    const Ntag21xMetadataHeader *header
);

/**
 * @brief Transform NTAG215 data to a different format
 *
 * Provided a NTAG215Data buffer and a signature buffer, this function
 * processes the data and header into a different format. The output format
 * can be specified as an enum value.
 * @param data Pointer to the NTAG215Data data.
 * @param header: Pointer to the Ntag21xProxmarkHeader buffer to save Proxmark 3 metadata into.
 * @param output_format The output format to transform to.
 * @param filename Path to the output file.
 * @return Transformed data
 */
char *ntag215_transform_format(
    const Ntag215Data *data,
    const Ntag21xMetadataHeader *header,
    FileFormat output_format,
    const char *filename
);

/**
 * @brief Read NTAG215 data from a file
 *
 * Provided a path to a file, a NTAG215Data buffer and a signature buffer,
 * this function will read the data from the file into the buffers. If the file
 * contains the signature, it will also be loaded. Returns error if the file
 * can't be opened, or the size is wrong.
 * @param filename Path to the file.
 * @param data Pointer to the NTAG215Data data.
 * @param header: Pointer to the Ntag21xProxmarkHeader buffer to save Proxmark 3 metadata into.
 * @return Status code
 */
RfidxStatus ntag215_read_from_file(
    const char *filename,
    Ntag215Data **data,
    Ntag21xMetadataHeader **header
);

#endif //LIBRFIDX_NTAG215_H
