/*
 * librfidx - Universal RFID Tag Format Parser and Converter
 *
 * Copyright (c) 2025. Firefox2100
 *
 * This software is released under the MIT License.
 * SPDX-License-Identifier: MIT
 */

#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include "mbedtls/md.h"
#include "mbedtls/aes.h"
#include "librfidx/application/amiibo.h"

static void derive_step(
    bool *used,
    uint16_t *iteration,
    uint8_t *buffer,
    const size_t buffer_size,
    mbedtls_md_context_t *hmac_context,
    uint8_t *output
) {
    if (*used) {
        mbedtls_md_hmac_reset(hmac_context);
    } else {
        *used = true;
    }

    buffer[0] = *iteration >> 8;
    buffer[1] = *iteration >> 0;
    (*iteration)++;

    mbedtls_md_hmac_update(hmac_context, buffer, buffer_size);
    mbedtls_md_hmac_finish(hmac_context, output);
}

RfidxStatus amiibo_derive_key(
    const DumpedKeySingle *input_key,
    const AmiiboData *amiibo_data,
    DerivedKey *derived_key
) {
    // Prepare seeds to derive the key
    uint8_t prepared_seed[480] = {0};

    uint8_t *curr = memccpy(prepared_seed, input_key->typeString, '\0', sizeof(input_key->typeString));
    const size_t leadingSeedBytes = 16 - input_key->magicBytesSize;
    memcpy(curr, amiibo_data->amiibo.write_counter, leadingSeedBytes);
    curr += leadingSeedBytes;
    memcpy(curr, input_key->magicBytes, input_key->magicBytesSize);
    curr += input_key->magicBytesSize;
    memcpy(curr, amiibo_data->amiibo.manufacturer_data.uid0, 8);
    memcpy(curr + 8, amiibo_data->amiibo.manufacturer_data.uid0, 8);
    curr += 16;

    for (unsigned int i = 0; i < 32; i++) {
        curr[i] = amiibo_data->amiibo.keygen_salt[i] ^ input_key->xorTable[i];
    }
    curr += 32;

    size_t prepared_seed_size = curr - prepared_seed;

    // Derive the keys using HMAC-SHA256
    bool used = false;
    uint16_t iterations = 0;
    size_t buffer_size = sizeof(uint16_t) + prepared_seed_size;
    uint8_t buffer[buffer_size];
    memcpy(buffer + sizeof(uint16_t), prepared_seed, prepared_seed_size);

    mbedtls_md_context_t hmac_context;
    mbedtls_md_init(&hmac_context);
    mbedtls_md_setup(&hmac_context, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1);
    mbedtls_md_hmac_starts(&hmac_context, input_key->hmacKey, sizeof(input_key->hmacKey));

    size_t output_size = sizeof(DerivedKey);
    curr = (uint8_t *)derived_key;
    while (output_size > 0) {
        if (output_size < 32) {
            uint8_t temp[32];
            derive_step(&used, &iterations, buffer, buffer_size, &hmac_context, temp);
            memcpy(curr, temp, output_size);
            break;
        }

        derive_step(&used, &iterations, buffer, buffer_size, &hmac_context, curr);
        curr += 32;
        output_size -= 32;
    }

    mbedtls_md_free(&hmac_context);

    return RFIDX_OK;
}

RfidxStatus amiibo_load_dumped_keys(const char* filename, DumpedKeys *dumped_keys) {
    FILE * f = fopen(filename, "rb");

    if (!f) {
        return RFIDX_AMIIBO_KEY_IO_ERROR;
    }

    if (fread(dumped_keys, sizeof(DumpedKeys), 1, f) != 1) {
        fclose(f);
        return RFIDX_AMIIBO_KEY_IO_ERROR;
    }
    fclose(f);

    if (
        (dumped_keys->data.magicBytesSize > 16) ||
        (dumped_keys->tag.magicBytesSize > 16)
    ) {
        return RFIDX_AMIIBO_KEY_IO_ERROR;
    }

    return RFIDX_OK;
}

RfidxStatus amiibo_save_dumped_keys(const char* filename, const DumpedKeys* keys) {
    FILE * f = fopen(filename, "wb");

    if (!f) {
        return RFIDX_AMIIBO_KEY_IO_ERROR;
    }

    if (!fwrite(keys, sizeof(DumpedKeys), 1, f)) {
        fclose(f);

        return RFIDX_AMIIBO_KEY_IO_ERROR;
    }
    fclose(f);

    return RFIDX_OK;
}

RfidxStatus amiibo_cipher(const DerivedKey *data_key, AmiiboData* amiibo_data) {
    // Prepare the AES context and IV
    mbedtls_aes_context aes;
    unsigned char nonce_counter[16];
    unsigned char stream_block[16];
    size_t nc_offset = 0;
    mbedtls_aes_setkey_enc(&aes, data_key->aesKey, 128);
    memset(nonce_counter, 0, sizeof(nonce_counter));
    memset(stream_block, 0, sizeof(stream_block));
    memcpy(nonce_counter, data_key->aesIV, sizeof(nonce_counter));

    // Prepare the data buffer
    const size_t buffer_size = sizeof(AmiiboTagConfig) + sizeof(AmiiboApplicationData);
    uint8_t in_buffer[buffer_size];
    uint8_t out_buffer[buffer_size];
    memcpy(in_buffer, &amiibo_data->amiibo.tag_configs, sizeof(AmiiboTagConfig));
    memcpy(in_buffer + sizeof(AmiiboTagConfig), &amiibo_data->amiibo.data, sizeof(AmiiboApplicationData));

    // Run the cypher in CTR mode
    mbedtls_aes_crypt_ctr(
        &aes,
        buffer_size,
        &nc_offset,
        nonce_counter,
        stream_block,
        in_buffer,
        out_buffer
    );

    // Copy the result back to the amiibo data
    memcpy(&amiibo_data->amiibo.tag_configs, out_buffer, sizeof(AmiiboTagConfig));
    memcpy(&amiibo_data->amiibo.data, out_buffer + sizeof(AmiiboTagConfig), sizeof(AmiiboApplicationData));

    return RFIDX_OK;
}
