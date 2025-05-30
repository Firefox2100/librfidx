set(TESTS
    test_ntag21x_validate_manufacturer_data
    test_ntag21x_randomize_uid
    test_ntag215_load_binary_dump
    test_ntag215_load_binary_dump_with_header
    test_ntag215_save_binary_and_reload
    test_ntag215_load_binary_dump_real
    test_ntag215_load_json_dump_real
    test_ntag215_save_json_dump_and_reload
    test_ntag215_load_nfc_dump_real
    test_ntag215_save_nfc_dump_and_reload
    test_amiibo_load_dumped_keys
    test_amiibo_derive_keys
    test_amiibo_validate_signature
    test_rfidx_randomize_uid_ntag215
    test_rfidx_randomize_uid_amiibo
)

foreach(TEST ${TESTS})
    add_test(NAME ${TEST} COMMAND unit_test ${TEST})
endforeach()