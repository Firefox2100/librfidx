set(TESTS
    test_ntag21x_validate_manufacturer_data
    test_ntag21x_validate_manufacturer_data_failed
    test_ntag21x_randomize_uid
    test_ntag21x_randomize_uid_failed
    test_ntag215_load_binary_dump
    test_ntag215_load_binary_dump_with_header
    test_ntag215_save_binary_and_reload
    test_ntag215_load_binary_dump_real
    test_ntag215_load_json_dump_real
    test_ntag215_save_json_dump_and_reload
    test_ntag215_load_nfc_dump_real
    test_ntag215_save_nfc_dump_and_reload
    test_amiibo_load_dumped_keys
    test_amiibo_save_dumped_keys_and_reload
    test_amiibo_derive_keys
    test_amiibo_cipher
    test_amiibo_validate_signature
    test_amiibo_generate
    test_amiibo_sign_payload
    test_amiibo_wipe
    test_rfidx_randomize_uid_ntag215
    test_rfidx_randomize_uid_amiibo
    test_rfidx_generate_amiibo
)

foreach(TEST ${TESTS})
    # Remove "test_" prefix
    string(REPLACE "test_" "" TEST_STRIPPED ${TEST})

    # Replace first underscore with "::"
    string(FIND "${TEST_STRIPPED}" "_" sep_index)
    if(NOT sep_index EQUAL -1)
        math(EXPR next_index "${sep_index} + 1")
        string(SUBSTRING "${TEST_STRIPPED}" 0 ${sep_index} ns)
        string(SUBSTRING "${TEST_STRIPPED}" ${next_index} -1 func)
        set(TEST_NAME "${ns}::${func}")
    else()
        set(TEST_NAME "${TEST_STRIPPED}")
    endif()

    add_test(NAME ${TEST_NAME} COMMAND unit_test ${TEST})
endforeach()

add_test(NAME all COMMAND unit_test)
