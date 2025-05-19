/*
 * librfidx - Universal RFID Tag Format Parser and Converter
 *
 * Copyright (c) 2025. Firefox2100
 *
 * This software is released under the MIT License.
 * SPDX-License-Identifier: MIT
 */

#ifndef LIBRFIDX_NTAG_COMMON_H
#define LIBRFIDX_NTAG_COMMON_H

#include <stdint.h>

#define RFIDX_NTAG21X_UID_ERROR -2048
#define RFIDX_NTAG21X_FIXED_BYTES_ERROR -2049

#define NTAG_SIGNATURE_SIZE 32

typedef uint8_t NtagSignature[NTAG_SIGNATURE_SIZE];

#endif //LIBRFIDX_NTAG_COMMON_H
