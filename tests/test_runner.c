/*
 * librfidx - Universal RFID Tag Format Parser and Converter
 *
 * Copyright (c) 2025. Firefox2100
 *
 * This software is released under the MIT License.
 * SPDX-License-Identifier: MIT
 */

#include <check.h>

extern Suite *ntag_suite(void);
extern Suite *application_suite(void);

int main(void) {
    int failed = 0;
    SRunner *sr = srunner_create(ntag_suite());
    srunner_set_fork_status(sr, CK_NOFORK);
    srunner_add_suite(sr, application_suite());

    srunner_run_all(sr, CK_NORMAL);
    failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (failed == 0) ? 0 : 1;
}
