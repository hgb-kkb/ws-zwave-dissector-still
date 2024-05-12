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

#ifndef __ZWAVE_SEC0_DECRYPT_H__
#define __ZWAVE_SEC0_DECRYPT_H__

#include "ws_symbol_export.h"

#define ZWAVE_SEC0_KEY_LENGTH   16
#define ZWAVE_SEC0_IV_LENGTH    16
#define ZWAVE_SEC0_NONCE_LENGTH 8
#define ZWAVE_AES128_OUT_LENGTH 16
#define ZWAVE_SEC0_MAC_LENGTH   8

typedef struct _recv_nonce {
    guint8      nonce[ZWAVE_SEC0_NONCE_LENGTH];
    guint32     frame_num;
} recv_nonce_t;

typedef enum _sec0_dec_status {
    DEC_NOT_POSSIBLE_NO_KEY,    // No matching key found
    DEC_FAILED_NO_RECV_NONCE,   // No matching receiver nonce found
    DEC_FAILED_GCRY_ERR,        // Error in gcrypt
    DEC_OK,                     // Decryption successfull, mac has not been checked
    DEC_OK_MAC_VALID,           // Decryption successfull, mac valid
    DEC_OK_MAC_INVALID,         // Decryption successfull, mac invalid
} sec0_dec_status_t;

// Initializes the decryption module
void
zwave_sec0_init(void);

// Resets the decryption module
void
zwave_sec0_reset(void);

// Registers a nonce from a SECURITY_NONCE_REPORT
void
zwave_sec0_register_nonce(recv_nonce_t *recv_nonce);

// Adds a key to the keyring if it does not exist already
// Returns FALSE if it already exists, else TRUE
gboolean
zwave_sec0_add_key(guint8 *network_key);

// Removes a key from the keyring specified by the network key
void
zwave_sec0_remove_key(guint8 *network_key);

// Decrypt data with a given sender nonce
// Returns the status of the operation
sec0_dec_status_t
zwave_sec0_decrypt(const guint8 *data, const guint data_len, const guint8 sender_nonce[ZWAVE_SEC0_NONCE_LENGTH], const guint8 recv_nonce_id, const guint frame_num, guint8 *dst, guint8 *mac, guint8 src_id, guint8 dst_id);

#endif // __ZWAVE_SEC0_DECRYPT_H__

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
