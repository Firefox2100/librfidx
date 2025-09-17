/*
 * librfidx - Universal RFID Tag Format Parser and Converter
 *
 * Copyright (c) 2025. Firefox2100
 *
 * This software is released under the MIT License.
 * SPDX-License-Identifier: MIT
 */

#include <stdio.h>
#include "librfidx/rfidx.h"

RfidxStatus main(const int argc, char **argv) {
    return rfidx_main(argc, argv, stdout, stderr);
}