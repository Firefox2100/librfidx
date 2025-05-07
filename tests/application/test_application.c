/*
 * librfidx - Universal RFID Tag Format Parser and Converter
 *
 * Copyright (c) 2025. Firefox2100
 *
 * This software is released under the MIT License.
 * SPDX-License-Identifier: MIT
 */

#include <check.h>

extern TCase *amiibo_key_io_case(void);
extern TCase *amiibo_key_cypher_case(void);

Suite *application_suite(void) {
    Suite *s = suite_create("Application");

    suite_add_tcase(s, amiibo_key_io_case());
    suite_add_tcase(s, amiibo_key_cypher_case());

    return s;
}
