/*
 * librfidx - Universal RFID Tag Format Parser and Converter
 *
 * Copyright (c) 2025. Firefox2100
 *
 * This software is released under the MIT License.
 * SPDX-License-Identifier: MIT
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include "mbedtls/md.h"
#include "mbedtls/aes.h"
#include "librfidx/application/amiibo_core.h"

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

    buffer[0] = (uint8_t)(*iteration >> 8);
    buffer[1] = (uint8_t)(*iteration >> 0);
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
    memcpy(curr, &amiibo_data->amiibo.manufacturer_data, 8);
    memcpy(curr + 8, &amiibo_data->amiibo.manufacturer_data, 8);
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

RfidxStatus amiibo_generate_signature(
    const DerivedKey *tag_key,
    const DerivedKey *data_key,
    const AmiiboData* amiibo_data,
    uint8_t *tag_hash,
    uint8_t *data_hash
) {
    uint8_t signing_buffer[480] = {0};
    memcpy(signing_buffer, amiibo_data->ntag215.bytes + 16, 36);
    memcpy(signing_buffer + 36, amiibo_data->amiibo.data.bytes, 360);
    memcpy(signing_buffer + 428, &amiibo_data->amiibo.manufacturer_data, 8);
    memcpy(signing_buffer + 436, amiibo_data->amiibo.model_info.bytes, 44);

    mbedtls_md_hmac(
        mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
        tag_key->hmacKey,
        sizeof(tag_key->hmacKey),
        signing_buffer + 428,
        52,
        tag_hash
    );

    memcpy(signing_buffer + 396, tag_hash, 32);

    mbedtls_md_hmac(
        mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
        data_key->hmacKey,
        sizeof(data_key->hmacKey),
        signing_buffer + 1,             // 1 byte offset, it does not take the fixed 0xA5 into calculation
        479,
        data_hash
    );

    return RFIDX_OK;
}

RfidxStatus amiibo_validate_signature(
    const DerivedKey *tag_key,
    const DerivedKey *data_key,
    const AmiiboData* amiibo_data
) {
    uint8_t tag_hash[32];
    uint8_t data_hash[32];

    const RfidxStatus status = amiibo_generate_signature(
        tag_key,
        data_key,
        amiibo_data,
        tag_hash,
        data_hash
    );

    if (status != RFIDX_OK) {
        return status;
    }

    if (memcmp(tag_hash, amiibo_data->amiibo.tag_hash, 32) != 0) {
        return RFIDX_AMIIBO_HMAC_VALIDATION_ERROR;
    }
    if (memcmp(data_hash, amiibo_data->amiibo.data_hash, 32) != 0) {
        return RFIDX_AMIIBO_HMAC_VALIDATION_ERROR;
    }

    return RFIDX_OK;
}

RfidxStatus amiibo_sign_payload(
    const DerivedKey *tag_key,
    const DerivedKey *data_key,
    AmiiboData* amiibo_data
) {
    const RfidxStatus status = amiibo_generate_signature(
        tag_key,
        data_key,
        amiibo_data,
        amiibo_data->amiibo.tag_hash,
        amiibo_data->amiibo.data_hash
    );

    return status;
}

RfidxStatus amiibo_format_dump(AmiiboData* amiibo_data, Ntag21xMetadataHeader *header) {
    // Tag manufacturer data
    amiibo_data->ntag215.structure.manufacturer_data.internal = 0x48;
    amiibo_data->ntag215.structure.manufacturer_data.lock[0] = 0x0F;
    amiibo_data->ntag215.structure.manufacturer_data.lock[1] = 0xE0;

    // Amiibo related fixed data. They are the same for all amiibo, but not
    // on all NTAG215
    amiibo_data->amiibo.fixed_a5 = 0xA5;
    memcpy(amiibo_data->amiibo.dynamic_lock, "\x01\x00\x0F", 3);
    amiibo_data->amiibo.reserved = 0xBD;
    memcpy(amiibo_data->amiibo.configuration.cfg0, "\x00\x00\x00\x04", 4);
    memcpy(amiibo_data->amiibo.configuration.cfg1, "\x5F\x00\x00\x00", 4);
    memcpy(amiibo_data->amiibo.capability, "\xF1\x10\xFF\xEE", 4);

    // Generate the tag password
    amiibo_data->ntag215.structure.configuration.passwd[0] =
        amiibo_data->ntag215.structure.manufacturer_data.uid0[1] ^
            amiibo_data->ntag215.structure.manufacturer_data.uid1[0] ^ 0xAA;
    amiibo_data->ntag215.structure.configuration.passwd[1] =
        amiibo_data->ntag215.structure.manufacturer_data.uid0[2] ^
            amiibo_data->ntag215.structure.manufacturer_data.uid1[1] ^ 0x55;
    amiibo_data->ntag215.structure.configuration.passwd[2] =
        amiibo_data->ntag215.structure.manufacturer_data.uid1[0] ^
            amiibo_data->ntag215.structure.manufacturer_data.uid1[2] ^ 0xAA;
    amiibo_data->ntag215.structure.configuration.passwd[3] =
        amiibo_data->ntag215.structure.manufacturer_data.uid1[1] ^
            amiibo_data->ntag215.structure.manufacturer_data.uid1[3] ^ 0x55;

    // PACK
    memcpy(amiibo_data->ntag215.structure.configuration.pack, "\x80\x80", 2);
    memcpy(amiibo_data->ntag215.structure.configuration.reserved, "\x00\x00", 2);

    // Metadata header
    memcpy(header->version, "\x00\x04\x04\x02\x01\x00\x11\x03", 8);
    header->memory_max = 134;

    return RFIDX_OK;
}

RfidxStatus amiibo_generate(
    const uint8_t *uuid,
    AmiiboData* amiibo_data,
    Ntag21xMetadataHeader *header
) {
    // Re-initialize the memory space
    memset(amiibo_data, 0, sizeof(AmiiboData));
    memset(header, 0, sizeof(Ntag21xMetadataHeader));

    const int ret = mbedtls_ctr_drbg_random(
        &rfidx_ctr_drbg,
        amiibo_data->amiibo.keygen_salt,
        sizeof(amiibo_data->amiibo.keygen_salt)
    );
    if (ret != 0) {
        return RFIDX_DRNG_ERROR;
    }

    // Set the UUID
    memcpy(amiibo_data->amiibo.model_info.bytes, uuid, 8);

    ntag21x_randomize_uid(&amiibo_data->ntag215.structure.manufacturer_data);

    // Format the dump
    amiibo_format_dump(amiibo_data, header);

    return RFIDX_OK;
}

RfidxStatus amiibo_wipe(
    AmiiboData* amiibo_data
) {
    // Clear application data
    memset(&amiibo_data->amiibo.data, 0, sizeof(AmiiboApplicationData));

    return RFIDX_OK;
}

RfidxStatus amiibo_transform_data(
    AmiiboData **amiibo_data,
    Ntag21xMetadataHeader **header,
    TransformCommand command,
    const uint8_t *uuid,
    const DumpedKeys *dumped_keys
) {
    if (command == TRANSFORM_NONE) {
        // Return early
        return RFIDX_OK;
    }

    if (command == TRANSFORM_GENERATE) {
        // Prepare the data first due to no input
        *amiibo_data = malloc(sizeof(AmiiboData));
        if (!*amiibo_data) {
            return RFIDX_MEMORY_ERROR;
        }

        *header = malloc(sizeof(Ntag21xMetadataHeader));
        if (!*header) {
            free(*amiibo_data);
            return RFIDX_MEMORY_ERROR;
        }

        // Generate the amiibo data
        const RfidxStatus status = amiibo_generate(uuid, *amiibo_data, *header);
        if (status != RFIDX_OK) {
            free(*amiibo_data);
            free(*header);
            return status;
        }
    }

    // Derive the keys
    DerivedKey tag_key = {0};
    DerivedKey data_key = {0};

    RfidxStatus status = amiibo_derive_key(&dumped_keys->tag, *amiibo_data, &tag_key);
    if (status != RFIDX_OK) {
        return status;
    }

    status = amiibo_derive_key(&dumped_keys->data, *amiibo_data, &data_key);
    if (status != RFIDX_OK) {
        return status;
    }

    switch (command) {
        case TRANSFORM_GENERATE:
            // Do nothing, the amiibo data is already generated
            break;
        case TRANSFORM_WIPE:
            // Decrypt the Amiibo data
            status = amiibo_cipher(&data_key, *amiibo_data);
            if (status != RFIDX_OK) {
                return status;
            }

            // Wipe the Amiibo data
            status = amiibo_wipe(*amiibo_data);
            if (status != RFIDX_OK) {
                return status;
            }

            break;
        case TRANSFORM_RANDOMIZE_UID:
            // Decrypt the Amiibo data
            status = amiibo_cipher(&data_key, *amiibo_data);
            if (status != RFIDX_OK) {
                return status;
            }

            // Randomize the UID
            status = ntag21x_randomize_uid(&(*amiibo_data)->ntag215.structure.manufacturer_data);
            if (status != RFIDX_OK) {
                return status;
            }

            break;
    }

    // Format the dump
    status = amiibo_format_dump(*amiibo_data, *header);
    if (status != RFIDX_OK) {
        return status;
    }

    // Sign and encrypt the tag
    status = amiibo_sign_payload(&tag_key, &data_key, *amiibo_data);
    if (status != RFIDX_OK) {
        return status;
    }

    status = amiibo_cipher(&tag_key, *amiibo_data);
    if (status != RFIDX_OK) {
        return status;
    }

    return RFIDX_OK;
}
