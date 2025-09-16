set(TESTS
    test_ntag21x_validate_manufacturer_data
    test_ntag21x_validate_manufacturer_data_failed
    test_ntag21x_randomize_uid
    test_ntag21x_randomize_uid_failed
    test_ntag215_parse_binary_data_only
    test_ntag215_parse_binary_with_header
    test_ntag215_parse_binary_invalid_length
    test_ntag215_serialize_binary
    test_ntag215_parse_header_from_json_success
    test_ntag215_parse_header_from_json_missing_fields
    test_ntag215_parse_header_from_json_invalid_hex
    test_ntag215_parse_data_from_json_success
    test_ntag215_parse_data_from_json_missing_or_invalid
    test_ntag215_parse_json_success
    test_ntag215_parse_json_errors
    test_ntag215_dump_header_to_json
    test_ntag215_dump_data_to_json
    test_ntag215_serialize_json
    test_ntag215_parse_nfc_success
    test_ntag215_parse_nfc_errors
    test_ntag215_serialize_nfc
    test_ntag215_generate_success
    test_ntag215_wipe
    test_ntag215_transform_data_none
    test_ntag215_transform_data_wipe
    test_ntag215_transform_data_generate
    test_ntag215_transform_data_randomize_uid_success
    test_ntag215_transform_data_randomize_uid_failure
    test_ntag215_transform_data_unknown
    test_ntag215_load_binary_dump
    test_ntag215_load_binary_dump_with_header
    test_ntag215_save_binary_and_reload
    test_ntag215_load_binary_dump_real
    test_ntag215_load_json_dump_real
    test_ntag215_save_json_dump_and_reload
    test_ntag215_load_nfc_dump_real
    test_ntag215_save_nfc_dump_and_reload
    test_mfc1k_load_binary_dump_real
    test_mfc1k_save_binary_and_reload
    test_mfc1k_load_json_dump_real
    test_mfc1k_save_json_dump_and_reload
    test_mfc1k_load_nfc_dump_real
    test_mfc1k_save_nfc_dump_and_reload
    test_amiibo_load_dumped_keys
    test_amiibo_save_dumped_keys_and_reload
    test_amiibo_derive_keys
    test_amiibo_cipher
    test_amiibo_validate_signature
    test_amiibo_generate
    test_amiibo_sign_payload
    test_amiibo_wipe
    test_rfidx_string_to_transform_command
    test_rfidx_read_tag_from_file_ntag215
    test_rfidx_read_tag_from_file_amiibo
    test_rfidx_read_tag_from_file_unknown
    test_rfidx_read_tag_from_file_missing
    test_rfidx_save_tag_to_file_binary
    test_rfidx_save_tag_to_file_invalid_format
    test_rfidx_transform_tag_ntag215_wipe
    test_rfidx_transform_tag_amiibo_missing_key
    test_rfidx_transform_tag_unknown
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
