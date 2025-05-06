/*
 * librfidx - Universal RFID Tag Format Parser and Converter
 *
 * Copyright (c) 2025. Firefox2100
 *
 * This software is released under the MIT License.
 * SPDX-License-Identifier: MIT
 */

#include <check.h>

extern TCase *ntag215_binary_io_case(void);
extern TCase *ntag215_json_io_case(void);
extern TCase *ntag215_nfc_io_case(void);

Suite *ntag_suite(void) {
    Suite *s = suite_create("NXP NTAG");

    suite_add_tcase(s, ntag215_binary_io_case());
    suite_add_tcase(s, ntag215_json_io_case());
    suite_add_tcase(s, ntag215_nfc_io_case());

    return s;
}
