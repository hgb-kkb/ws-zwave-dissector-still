/* packet-zwave-sec0-decrypt.h
 * Decryption functions and keys for Z-Wave SEC0
 * Copyright 2021, Barger, Knoll & Kofler <si@iot.at>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <epan/wmem/wmem.h>
#include <wsutil/wsgcrypt.h>
#include "proto.h"

#include "packet-zwave-sec0-decrypt.h"

#define HANDSHAKE_DATA_SIZE     19
#define AUTH_DATA_MIN_SIZE      20

typedef struct _key_entry {
    guint8 net_key[ZWAVE_SEC0_KEY_LENGTH];
    guint8 enc_key[ZWAVE_SEC0_KEY_LENGTH];
    guint8 auth_key[ZWAVE_SEC0_KEY_LENGTH];
} key_entry_t;

// Initial handshake keys
static key_entry_t sec0_handshake_key = {
/    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    {0x85, 0x22, 0x71, 0x7d, 0x3a, 0xd1, 0xfb, 0xfe, 0xaf, 0xa1, 0xce, 0xaa, 0xfd, 0xf5, 0x65, 0x65},
    {0x9a, 0xda, 0xe0, 0x54, 0xf6, 0x3d, 0xfa, 0xff, 0x5e, 0xa1, 0x8e, 0x45, 0xed, 0xf6, 0xea, 0x6f},
};

/* Memory structures for keys and nonces */
static wmem_map_t *key_map = NULL;
static wmem_array_t *nonce_array = NULL;


/* Private functions */

static gboolean
nonce_array_contains(recv_nonce_t *recv_nonce)
{
    for (guint array_idx = 0; array_idx < wmem_array_get_count(nonce_array); array_idx++) {
        recv_nonce_t *curr_elem = (recv_nonce_t *) wmem_array_index(nonce_array, array_idx);

        if (curr_elem->frame_num == recv_nonce->frame_num) {
            if (memcmp(curr_elem->nonce, recv_nonce->nonce, ZWAVE_SEC0_NONCE_LENGTH) == 0) {
                return TRUE;
            }
        }
    }
    return FALSE;
}

static gboolean
key_array_contains_net_key(guint8 *net_key)
{
    wmem_list_t *key_list = wmem_map_get_keys(wmem_packet_scope(), key_map);
    wmem_list_frame_t *curr_key_id = wmem_list_head(key_list);
    for (; curr_key_id != NULL; curr_key_id = wmem_list_frame_next(curr_key_id)) {
        key_entry_t *curr_key = (key_entry_t *)wmem_map_lookup(key_map, wmem_list_frame_data(curr_key_id));

        if(memcmp(curr_key->net_key, net_key, ZWAVE_SEC0_KEY_LENGTH) == 0) {
            return TRUE;
        }
    }

    return FALSE;
}

static recv_nonce_t*
find_recv_nonce(const guint8 recv_nonce_id, const guint32 frame_num)
{
    for (guint array_idx = 0; array_idx < wmem_array_get_count(nonce_array); array_idx++) {
        recv_nonce_t *curr_elem = (recv_nonce_t *) wmem_array_index(nonce_array, array_idx);

        if (curr_elem->frame_num < frame_num) {
            if (curr_elem->nonce[0] == recv_nonce_id) {
                return curr_elem;
            }
        }
    }
    return NULL;
}

static gboolean
compute_subkeys(guint8 *network_key)
{
    guint8 *key = NULL;
    const guint8 enc_data[ZWAVE_SEC0_KEY_LENGTH] =
        {0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA};
    const guint8 auth_data[ZWAVE_SEC0_KEY_LENGTH] =
        {0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55};
    gcry_error_t err = 0;
    gcry_cipher_hd_t cipher_hd = NULL;

    key = (guint8 *)wmem_alloc(NULL, ZWAVE_SEC0_KEY_LENGTH);

    if (wmem_map_contains(key_map, network_key)) {
        return FALSE;
    }

    err = gcry_cipher_open(&cipher_hd, GCRY_CIPHER_AES, GCRY_CIPHER_MODE_ECB, 0);
    if (err) {
        fprintf(stderr, "<Z-Wave/Sec0 Dissector> Error in encryption, grcy_open_cipher_failed: %s\n", gcry_strerror(err));
        return FALSE;
    }

    // Set key
    err = gcry_cipher_setkey(cipher_hd, network_key, ZWAVE_SEC0_KEY_LENGTH);
    if (err) {
        fprintf(stderr, "<Z-Wave/Sec0 Dissector> Error in encryption, grcy_cipher_setkey_failed: %s\n", gcry_strerror(err));
        gcry_cipher_close(cipher_hd);
        return FALSE;
    }

    // Build new key entry
    key_entry_t *new_entry = (key_entry_t *) wmem_alloc(NULL, sizeof(key_entry_t));
    memcpy(new_entry->net_key, network_key, ZWAVE_SEC0_KEY_LENGTH);

    // Compute encryption key
    err = gcry_cipher_encrypt(cipher_hd, key, ZWAVE_SEC0_KEY_LENGTH, enc_data, sizeof(enc_data));
    if (err) {
        fprintf(stderr, "<Z-Wave/Sec0 Dissector> Error in encryption, grcy_cipher_encrypt_failed: %s\n", gcry_strerror(err));
        gcry_cipher_close(cipher_hd);
        wmem_free(NULL, key);
        wmem_free(NULL, new_entry);
        return FALSE;
    } else {
        // Add encryption key to key entry
        memcpy(new_entry->enc_key, key, ZWAVE_SEC0_KEY_LENGTH);
    }

    // Compute authentication key
    err = gcry_cipher_encrypt(cipher_hd, key, ZWAVE_SEC0_KEY_LENGTH, auth_data, sizeof(auth_data));
    if (err) {
        fprintf(stderr, "<Z-Wave/Sec0 Dissector> Error in encryption, grcy_cipher_encrypt_failed: %s\n", gcry_strerror(err));
        gcry_cipher_close(cipher_hd);
        wmem_free(NULL, key);
        wmem_free(NULL, new_entry);
        return FALSE;
    } else {
        // Add authentication key to key entry
        memcpy(new_entry->auth_key, key, ZWAVE_SEC0_KEY_LENGTH);
    }

    // Add key to keyring
    wmem_map_insert(key_map, network_key, (void *)new_entry);

    wmem_free(NULL, key);
    return TRUE;
}

static gboolean
validate_mac(guint8* data, guint8 data_len, guint8 *mac, guint8 *iv, guint8 *auth_key, guint8 src_id, guint8 dst_id) {
    gboolean valid = FALSE;
    guint8 *auth_data = NULL;
    guint8 mac_iv[ZWAVE_SEC0_IV_LENGTH] = {0x00};
    guint8 *calc_mac = NULL;
    guint auth_data_len = (1 + ((AUTH_DATA_MIN_SIZE + data_len) / 16)) * 16;
    gcry_error_t err = 0;
    gcry_cipher_hd_t cipher_hd = NULL;
    
    // Allocate memory and initialize it
    auth_data = (guint8 *)wmem_alloc0(NULL, auth_data_len);
    calc_mac = (guint8 *)wmem_alloc(NULL, ZWAVE_AES128_OUT_LENGTH);

    // Build authentication data
    memcpy(auth_data, iv, ZWAVE_SEC0_IV_LENGTH);
    auth_data[16] = 0x81;
    auth_data[17] = src_id;
    auth_data[18] = dst_id;
    auth_data[19] = data_len;
    memcpy(auth_data + AUTH_DATA_MIN_SIZE, data, data_len);

    // Start encryption
    err = gcry_cipher_open(&cipher_hd, GCRY_CIPHER_AES, GCRY_CIPHER_MODE_CBC, GCRY_CIPHER_CBC_MAC);
    if (err) {
        fprintf(stderr, "<Z-Wave/Sec0 Dissector> Error in encryption, grcy_open_cipher_failed: %s\n", gcry_strerror(err));
        return valid;
    }

    // Set IV
    err = gcry_cipher_setiv(cipher_hd, mac_iv, ZWAVE_SEC0_IV_LENGTH);
    if (err) {
        fprintf(stderr, "<Z-Wave/Sec0 Dissector> Error in decryption, grcy_cipher_setiv_failed: %s\n", gcry_strerror(err));
        gcry_cipher_close(cipher_hd);
        return valid;
    }

    // Set key
    err = gcry_cipher_setkey(cipher_hd, auth_key, ZWAVE_SEC0_KEY_LENGTH);
    if (err) {
        fprintf(stderr, "<Z-Wave/Sec0 Dissector> Error in encryption, grcy_cipher_setkey_failed: %s\n", gcry_strerror(err));
        gcry_cipher_close(cipher_hd);
        return valid;
    }

    // Calculate mac
    calc_mac = (guint8 *)wmem_alloc(NULL, ZWAVE_AES128_OUT_LENGTH);
    err = gcry_cipher_encrypt(cipher_hd, calc_mac, ZWAVE_AES128_OUT_LENGTH, auth_data, auth_data_len);
    if (err) {
        fprintf(stderr, "<Z-Wave/Sec0 Dissector> Error in encryption, grcy_cipher_encrypt_failed: %s\n", gcry_strerror(err));
        gcry_cipher_close(cipher_hd);
    }

    valid = memcmp(mac, calc_mac, ZWAVE_SEC0_MAC_LENGTH) == 0;
    wmem_free(NULL, auth_data);
    wmem_free(NULL, calc_mac);
    return valid;
}


/* Exported functions */

// Initializes the decryption module
void
zwave_sec0_init(void) {
    // Create nonce array and key array
    if (nonce_array == NULL) {
        nonce_array = wmem_array_new(NULL, sizeof(recv_nonce_t));
    }
    if (key_map == NULL) {
        key_map = wmem_map_new(NULL, g_direct_hash, g_direct_equal);
        wmem_map_insert(key_map, sec0_handshake_key.net_key, (void *)&sec0_handshake_key);
    }
}

// Resets the decryption module
void
zwave_sec0_reset(void)
{
    // Free the nonce array and key array
    if (nonce_array != NULL) {
        wmem_destroy_array(nonce_array);
    }
    if (key_map != NULL) {
        wmem_free(NULL, key_map);
    }
}

// Registers a nonce from a SECURITY_NONCE_REPORT
void
zwave_sec0_register_nonce(recv_nonce_t *recv_nonce)
{
    // Insert nonce if it is not yet in array
    if ( nonce_array != FALSE && nonce_array_contains(recv_nonce) == FALSE) {
        wmem_array_append_one(nonce_array, *recv_nonce);
    }
}

// Adds a key to the keyring if it does not exist already
// Returns FALSE if it already exists or the key store has not been initialized, else TRUE
gboolean
zwave_sec0_add_key(guint8 *network_key)
{
    if (key_map == NULL) {
        return FALSE;
    }
    return compute_subkeys(network_key);
}

// Removes a key from the keyring specified by the network key
void
zwave_sec0_remove_key(guint8 *network_key)
{
    key_entry_t *entry = (key_entry_t *)wmem_map_remove(key_map, network_key);
    if (entry != NULL) {
        wmem_free(NULL, entry);
    }
}

// Decrypt data with a given sender nonce
sec0_dec_status_t
zwave_sec0_decrypt(const guint8 *data, const guint data_len, const guint8 sender_nonce[ZWAVE_SEC0_NONCE_LENGTH], const guint8 recv_nonce_id, const guint frame_num, guint8 *dst, guint8 *mac, guint8 src_id, guint8 dst_id)
{
    if (key_map == NULL) {
        return DEC_NOT_POSSIBLE_NO_KEY;
    }
    if (nonce_array == NULL) {
        return DEC_FAILED_NO_RECV_NONCE;
    }

    const guint8 key_set_cmd[3] = {0x00, 0x98, 0x06};
    gcry_error_t err = 0;
    gcry_cipher_hd_t cipher_hd = NULL;

    err = gcry_cipher_open(&cipher_hd, GCRY_CIPHER_AES, GCRY_CIPHER_MODE_OFB, 0);

    if (err) {
        fprintf(stderr, "<Z-Wave/Sec0 Dissector> Error in decryption, grcy_open_cipher_failed: %s\n", gcry_strerror(err));
        return DEC_FAILED_GCRY_ERR;
    }

    // Creation of cipher successfull, set the iv
    guint8 *iv = NULL;

    // Get receiver nonce
    // If no matching receiver nonce has been found return error
    recv_nonce_t *recv_nonce = find_recv_nonce(recv_nonce_id, frame_num);
    if (recv_nonce == NULL) {
        return DEC_FAILED_NO_RECV_NONCE;
    }

    // Create IV: sender_nonce || recv_nonce
    iv = (guint8 *)wmem_alloc(NULL, ZWAVE_SEC0_IV_LENGTH);
    memcpy(iv, sender_nonce, ZWAVE_SEC0_NONCE_LENGTH);
    memcpy(iv+ZWAVE_SEC0_NONCE_LENGTH, recv_nonce->nonce, ZWAVE_SEC0_NONCE_LENGTH);

    // Generation of IV successfull, try to decrypt
    wmem_list_t *key_list = wmem_map_get_keys(wmem_packet_scope(), key_map);
    wmem_list_frame_t *curr_key_id = wmem_list_head(key_list);
    for (; curr_key_id != NULL; curr_key_id = wmem_list_frame_next(curr_key_id)) {
        // Reset cipher and set IV
        gcry_cipher_reset(cipher_hd);
        err = gcry_cipher_setiv(cipher_hd, iv, ZWAVE_SEC0_IV_LENGTH);
        
        if (err) {
            fprintf(stderr, "<Z-Wave/Sec0 Dissector> Error in decryption, grcy_cipher_setiv_failed: %s\n", gcry_strerror(err));
            gcry_cipher_close(cipher_hd);
            return DEC_FAILED_GCRY_ERR;
        }

        // Set key
        key_entry_t *curr_key = (key_entry_t *)wmem_map_lookup(key_map, wmem_list_frame_data(curr_key_id));
        err = gcry_cipher_setkey(cipher_hd, curr_key->enc_key, ZWAVE_SEC0_KEY_LENGTH);
        if (err) {
            fprintf(stderr, "<Z-Wave/Sec0 Dissector> Error in decryption, grcy_cipher_setkey_failed: %s\n", gcry_strerror(err));
            gcry_cipher_close(cipher_hd);
            return DEC_FAILED_GCRY_ERR;
        }

        err = gcry_cipher_decrypt(cipher_hd, dst, data_len, data, data_len);

        if (err) {
            fprintf(stderr, "<Z-Wave/Sec0 Dissector> Error in decryption, grcy_cipher_decrypt_failed: %s\n", gcry_strerror(err));
            gcry_cipher_close(cipher_hd);
        }

        // If the properties byte is 0x00 the decyrption has been successfull
        if (dst[0] == 0x00) {
            // Check if a network key has been found
            if (data_len == HANDSHAKE_DATA_SIZE && memcmp(dst, key_set_cmd, 3) == 0) {
                // Compute and store encryption key if it has been found
                if (key_array_contains_net_key(dst+3) == FALSE) {
                    compute_subkeys(dst+3);
                }
            }

            sec0_dec_status_t dec_status = DEC_OK;
            // Check the MAC for validity if a mac has been given
            if (mac != NULL) {
                if (validate_mac((guint8 *)data, data_len, mac, iv, curr_key->auth_key, src_id, dst_id) == TRUE) {
                    dec_status = DEC_OK_MAC_VALID;
                } else {
                    dec_status = DEC_OK_MAC_INVALID;
                }
            }

            wmem_free(NULL, iv);
            return dec_status;
        }
    }

    wmem_free(NULL, iv);
    return DEC_NOT_POSSIBLE_NO_KEY;
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
