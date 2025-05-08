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

#include "librfidx/ntag/ntag215_core.h"

#ifndef LIBRFIDX_NO_PLATFORM

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

#endif

#endif //LIBRFIDX_NTAG215_H
