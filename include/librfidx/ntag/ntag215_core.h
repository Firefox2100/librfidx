/*
 * librfidx - Universal RFID Tag Format Parser and Converter
 *
 * Copyright (c) 2025. Firefox2100
 *
 * This software is released under the MIT License.
 * SPDX-License-Identifier: MIT
 */

#ifndef LIBRFIDX_NTAG215_CORE_H
#define LIBRFIDX_NTAG215_CORE_H

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
 * @brief Parse binary data into NTAG215 data and header
 *
 * Provided binary data read from a file, a NTAG215Data buffer and a signature buffer, this function
 * processes the binary data and loads the data into the buffers. If the binary data
 * is malformed, or the data is not in the expected format, it will return an error.
 * @param buffer The binary data to parse.
 * @param len The length of the binary data.
 * @param ntag215 Pointer to the NTAG215Data data.
 * @param header: Pointer to the Ntag21xMetadataHeader buffer to save tag metadata into.
 * @return Status code
 */
RfidxStatus ntag215_parse_binary(
    const uint8_t *buffer,
    size_t len,
    Ntag215Data *ntag215,
    Ntag21xMetadataHeader *header
);

/**
 * @brief Serialize NTAG215 data and header to binary
 *
 * Provided a NTAG215Data buffer and a signature buffer, this function
 * processes the data and header into a binary format.
 * @param ntag215 Pointer to the NTAG215Data data.
 * @param header: Pointer to the Ntag21xMetadataHeader buffer to save tag metadata into.
 * @return Binary data
 */
uint8_t *ntag215_serialize_binary(
    const Ntag215Data *ntag215,
    const Ntag21xMetadataHeader *header
);

/**
 * @brief Parse a JSON string into NTAG215 data and header
 *
 * Provided a JSON string, a NTAG215Data buffer and a signature buffer, this function
 * processes the JSON string and loads the data into the buffers. If the JSON string
 * is malformed, or the data is not in the expected format, it will return an error.
 * @param json_str The JSON string to parse.
 * @param ntag215 Pointer to the NTAG215Data data.
 * @param header: Pointer to the Ntag21xMetadataHeader buffer to save tag metadata into.
 * @return Status code
 */
RfidxStatus ntag215_parse_json(
    const char *json_str,
    Ntag215Data *ntag215,
    Ntag21xMetadataHeader *header
);

/**
 * @brief Serialize NTAG215 data and header to JSON string
 *
 * Provided a NTAG215Data buffer and a signature buffer, this function
 * processes the data and header into a JSON string.
 * @param ntag215 Pointer to the NTAG215Data data.
 * @param header: Pointer to the Ntag21xMetadataHeader buffer to save tag metadata into.
 * @return JSON string
 */
char *ntag215_serialize_json(
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
 * @param header: Pointer to the Ntag21xMetadataHeader buffer to save tag metadata into.
 * @return Status code
 */
RfidxStatus ntag215_parse_nfc(
    const char *nfc_str,
    Ntag215Data *ntag215,
    Ntag21xMetadataHeader *header
);

/**
 * @brief Serialize NTAG215 data and header to NFC string
 *
 * Provided a NTAG215Data buffer and a signature buffer, this function
 * processes the data and header into a NFC string.
 * @param ntag215 Pointer to the NTAG215Data data.
 * @param header: Pointer to the Ntag21xMetadataHeader buffer to save tag metadata into.
 * @return NFC string
 */
char *ntag215_serialize_nfc(
    const Ntag215Data *ntag215,
    const Ntag21xMetadataHeader *header
);

/**
 * @brief Generate a blank NTAG215 data structure
 *
 * This function generates a minimal working dump of an NTAG215 tag.
 * All user memory is left blank, no block is locked, and no configuration added except for
 * default ones. It behaves as a freshly made tag.
 * @param ntag215 Pointer to the NTAG215Data data to fill.
 * @param header Pointer to the Ntag21xMetadataHeader buffer to save tag metadata into.
 * @return Status code
 */
RfidxStatus ntag215_generate(
    Ntag215Data* ntag215,
    Ntag21xMetadataHeader *header
);

/**
 * @brief Wipe an NTAG215 dump
 *
 * This function wipes the NTAG215 data structure, setting everything back to factory defaults.
 * Essentially the result is a new tag with the same UID as input.
 * @param ntag215 Pointer to the NTAG215Data data to wipe.
 * @return Status code
 */
RfidxStatus ntag215_wipe(Ntag215Data* ntag215);

/**
 * @brief Transform NTAG215 data
 *
 * This function transforms the NTAG215 data based on the provided command.
 * @param ntag215 Pointer to the NTAG215Data data to transform.
 * @param header Pointer to the Ntag21xMetadataHeader buffer to save tag metadata into.
 * @param command The transformation command to apply.
 * @return Status code
 */
RFIDX_EXPORT RfidxStatus ntag215_transform_data(
    Ntag215Data **ntag215,
    Ntag21xMetadataHeader **header,
    TransformCommand command
);

_Static_assert(sizeof(Ntag215Raw) == NTAG215_TOTAL_BYTES, "NTAG215 raw data size mismatch");
_Static_assert(sizeof(Ntag215Structure) == NTAG215_TOTAL_BYTES, "NTAG215 structure size mismatch");
_Static_assert(sizeof(Ntag215Data) == NTAG215_TOTAL_BYTES, "NTAG215 data size mismatch");

#endif //LIBRFIDX_NTAG215_CORE_H
