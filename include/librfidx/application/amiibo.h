/*
 * librfidx - Universal RFID Tag Format Parser and Converter
 *
 * Copyright (c) 2025. Firefox2100
 *
 * This software is released under the MIT License.
 * SPDX-License-Identifier: MIT
 */

#ifndef LIBRFIDX_AMIIBO_H
#define LIBRFIDX_AMIIBO_H

#include "librfidx/application/amiibo_core.h"


#ifndef LIBRFIDX_NO_PLATFORM

RFIDX_EXPORT RfidxStatus amiibo_load_dumped_keys(const char* filename, DumpedKeys *dumped_keys);
RfidxStatus amiibo_save_dumped_keys(const char* filename, const DumpedKeys* keys);

#endif

#endif //LIBRFIDX_AMIIBO_H
