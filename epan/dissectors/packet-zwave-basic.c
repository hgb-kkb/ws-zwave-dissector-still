/* packet-zwave.c
 * Routines for Z-Wave dissection
 * Copyright 2021, Barger, Knoll & Kofler <si@iot.at>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * (A short description of the protocol including links to specifications,
 *  detailed documentation, etc.)
 */

#include <config.h>

#include <epan/expert.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/strutil.h>
#include <epan/uat.h>
#include "wmem/wmem.h"
#include "wsutil/crc16.h"

#include <stdio.h>

#include "packet-zwave.h"

#define CRC16_SEED 0x1D0F

/* Decryption keys */
static guint num_uat_key_records = 0;

typedef struct {
    gchar *string;
    guint8 net_key[ZWAVE_SEC0_KEY_LENGTH];
} uat_key_record_t;

static uat_key_record_t *zwave_sec0_uat_key_records = NULL;
static uat_t *zwave_sec0_key_table_uat;

/* UAT */
UAT_CSTRING_CB_DEF(zwave_sec0_uat_key_records, string, uat_key_record_t)

#define COMMAND_CLASS_SECURITY_V1 0x98
/* @command_class_defines@ */

#define COMMAND_CLASS_SECURITY_V1_NETWORK_KEY_SET 0x06
#define COMMAND_CLASS_SECURITY_V1_NETWORK_KEY_VERIFY 0x07
#define COMMAND_CLASS_SECURITY_V1_SECURITY_COMMANDS_SUPPORTED_GET 0x02
#define COMMAND_CLASS_SECURITY_V1_SECURITY_COMMANDS_SUPPORTED_REPORT 0x03
#define COMMAND_CLASS_SECURITY_V1_SECURITY_MESSAGE_ENCAPSULATION 0x81
#define COMMAND_CLASS_SECURITY_V1_SECURITY_MESSAGE_ENCAPSULATION_NONCE_GET 0xC1
#define COMMAND_CLASS_SECURITY_V1_SECURITY_NONCE_GET 0x40
#define COMMAND_CLASS_SECURITY_V1_SECURITY_NONCE_REPORT 0x80
#define COMMAND_CLASS_SECURITY_V1_SECURITY_SCHEME_GET 0x04
#define COMMAND_CLASS_SECURITY_V1_SECURITY_SCHEME_INHERIT 0x08
#define COMMAND_CLASS_SECURITY_V1_SECURITY_SCHEME_REPORT 0x05
/* @command_defines@ */

/* Enum for Z-Wave PDU types */
typedef enum _zwave_pdu_type {
    PDU_TYPE_UNKNOWN,
    PDU_TYPE_R1_R2,
    PDU_TYPE_R3,
} zwave_pdu_type;

static const value_string zwave_sec0_dec_status[] = {
    {0x00, "No valid key found"},
    {0x01, "No matching receiver nonce found"},
    {0x02, "Error in gcrypt"},
    {0x03, "Successful"},
    {0x04, "Successful"},
    {0x05, "Successful"},
};

static const value_string zwave_frame_types[] = {
    {0x01, "Singlecast MPDU"},
    {0x02, "Multicast MPDU"},
    {0x03, "Acknowledgement MPDU"},
    {0x08, "Router MPDU"},
};

static const value_string zwave_cmd_classes[] = {
    {COMMAND_CLASS_SECURITY_V1, "Command Class Security" },
/* @zwave_cmd_classes_entries@ */

};

static const value_string zwave_command_class_security_v1_commands[] = { 
    { COMMAND_CLASS_SECURITY_V1_NETWORK_KEY_SET, "Network Key Set"},
    { COMMAND_CLASS_SECURITY_V1_NETWORK_KEY_VERIFY, "Network Key Verify"},
    { COMMAND_CLASS_SECURITY_V1_SECURITY_COMMANDS_SUPPORTED_GET, "Security Commands Supported Get"},
    { COMMAND_CLASS_SECURITY_V1_SECURITY_COMMANDS_SUPPORTED_REPORT, "Security Commands Supported Report"},
    { COMMAND_CLASS_SECURITY_V1_SECURITY_MESSAGE_ENCAPSULATION, "Security Message Encapsulation"},
    { COMMAND_CLASS_SECURITY_V1_SECURITY_MESSAGE_ENCAPSULATION_NONCE_GET, "Security Message Encapsulation Nonce Get"},
    { COMMAND_CLASS_SECURITY_V1_SECURITY_NONCE_GET, "Security Nonce Get"},
    { COMMAND_CLASS_SECURITY_V1_SECURITY_NONCE_REPORT, "Security Nonce Report"},
    { COMMAND_CLASS_SECURITY_V1_SECURITY_SCHEME_GET, "Security Scheme Get"},
    { COMMAND_CLASS_SECURITY_V1_SECURITY_SCHEME_INHERIT, "Security Scheme Inherit"},
    { COMMAND_CLASS_SECURITY_V1_SECURITY_SCHEME_REPORT, "Security Scheme Report"},
};
/* @value_strings@ */

/* Prototypes */
/* (Required to prevent [-Wmissing-prototypes] warnings */
void proto_reg_handoff_zwave(void);
void proto_register_zwave(void);
void dissect_cmd_class (tvbuff_t *, packet_info *, proto_tree *, guint8, guint8, guint8 src_id, guint8 dst_id);
void prefs_zwave_apply(void);

/* Initialize the protocol and registered fields */
static int proto_zwave = -1;
static int hf_zwave_home_id = -1;
static int hf_zwave_src = -1;
static int hf_zwave_frame_ctrl = -1;
static int hf_zwave_routed = -1;
static int hf_zwave_ack_req = -1;
static int hf_zwave_low_pwr = -1;
static int hf_zwave_speed_mod = -1;
static int hf_zwave_frame_type = -1;
static int hf_zwave_seq = -1;
static int hf_zwave_dst = -1;
static int hf_zwave_len = -1;
static int hf_zwave_checksum_r1_r2 = -1;
static int hf_zwave_checksum_r3 = -1;
static int hf_zwave_checksum_status = -1;

static int hf_zwave_generic_cmd_class = -1;

static int hf_command_class_security_v1 = -1;
static int hf_command_class_security_v1_network_key_set_network_key_byte = -1;
static int hf_command_class_security_v1_security_commands_supported_report_reports_to_follow = -1;
static int hf_command_class_security_v1_security_commands_supported_report_command_class_support = -1;
static int hf_command_class_security_v1_security_commands_supported_report_command_class_mark = -1;
static int hf_command_class_security_v1_security_commands_supported_report_command_class_control = -1;
static int hf_command_class_security_v1_security_message_encapsulation_initialization_vector_byte = -1;
static int hf_command_class_security_v1_security_message_encapsulation_properties1 = -1;
static int hf_command_class_security_v1_security_message_encapsulation_command_byte = -1;
static int hf_command_class_security_v1_security_message_encapsulation_receivers_nonce_identifier = -1;
static int hf_command_class_security_v1_security_message_encapsulation_message_authentication_code_byte = -1;
static int hf_command_class_security_v1_security_message_encapsulation_nonce_get_initialization_vector_byte = -1;
static gint command_class_security_v1_security_message_encapsulation_nonce_get_properties1_subtree = -1; 
static int hf_command_class_security_v1_security_message_encapsulation_nonce_get_properties1 = -1;
static int hf_command_class_security_v1_security_message_encapsulation_nonce_get_properties1_bitflag_sequenced = -1;
static int hf_command_class_security_v1_security_message_encapsulation_nonce_get_properties1_bitflag_secondframe = -1;
static int hf_command_class_security_v1_security_message_encapsulation_nonce_get_properties1_bitfield_sequencecounter = -1;
static int hf_command_class_security_v1_security_message_encapsulation_nonce_get_properties1_bitfield_reserved = -1;
static int * const command_class_security_v1_security_message_encapsulation_nonce_get_properties1_structbyte_fields[] = {
    &hf_command_class_security_v1_security_message_encapsulation_nonce_get_properties1_bitflag_sequenced,
    &hf_command_class_security_v1_security_message_encapsulation_nonce_get_properties1_bitflag_secondframe,
    &hf_command_class_security_v1_security_message_encapsulation_nonce_get_properties1_bitfield_sequencecounter,
    &hf_command_class_security_v1_security_message_encapsulation_nonce_get_properties1_bitfield_reserved,
    NULL
};
static int hf_command_class_security_v1_security_message_encapsulation_nonce_get_command_byte = -1;
static int hf_command_class_security_v1_security_message_encapsulation_nonce_get_receivers_nonce_identifier = -1;
static int hf_command_class_security_v1_security_message_encapsulation_nonce_get_message_authentication_code_byte = -1;
static int hf_command_class_security_v1_security_nonce_report_nonce_byte = -1;
static int hf_command_class_security_v1_security_scheme_get_supported_security_schemes = -1;
static int hf_command_class_security_v1_security_scheme_inherit_supported_security_schemes = -1;
static int hf_command_class_security_v1_security_scheme_report_supported_security_schemes = -1;
/* @hf_definitions@ */


static expert_field ei_zwave_expert = EI_INIT;

/* Initialize the subtree pointers */
static gint ett_zwave = -1;
static gint ett_zwave_frame_ctrl = -1;
static gint ett_zwave_cmd_class = -1;
static gint ett_zwave_sec0_decrypted = -1;

#define ZWAVE_MIN_LENGTH 8

/*
 * Callback functions for the uat
 */

/* UAT record copy callback */
static void *
uat_key_record_copy_cb(void *n, const void *o, size_t size _U_)
{
    uat_key_record_t *new_rec = (uat_key_record_t *)n;
    const uat_key_record_t *old_rec = (const uat_key_record_t *)o;

    new_rec->string = g_strdup(old_rec->string);
    memcpy(new_rec->net_key, old_rec->net_key, ZWAVE_SEC0_KEY_LENGTH);

    return new_rec;
}

/* UAT record free callback */
static void
uat_key_record_free_cb(void *r)
{
    uat_key_record_t *rec = (uat_key_record_t *)r;
    zwave_sec0_remove_key(rec->net_key);
    g_free(rec->string);
}

/* UAT record update callback */
static gboolean
uat_key_record_update_cb(void *r, char **err)
{
    gboolean status = FALSE;
    uat_key_record_t *rec = (uat_key_record_t *)r;
    GByteArray *key_bytes = g_byte_array_new();

    if (rec->string == NULL) {
        *err = g_strdup("Key can't be blank.");
        return status;
    } else if (strlen(rec->string) != ZWAVE_SEC0_KEY_LENGTH*2) {
        *err = g_strdup("Key has to be a 16 byte hex string (32 chars).");
        return status;
    }

    // Check if the hex string is valid and convert it
    if (rec->string[0] != 0 && hex_str_to_bytes(rec->string, key_bytes, FALSE) == TRUE) {
        if (key_bytes->len == ZWAVE_SEC0_KEY_LENGTH) {
            memcpy(rec->net_key, key_bytes->data, ZWAVE_SEC0_KEY_LENGTH);
            zwave_sec0_add_key(rec->net_key);
            status = TRUE;
        } else {
            *err = g_strdup("Invalid hexstring.");
        }
    } else {
        *err = g_strdup("Invalid hexstring.");
    }

    g_byte_array_free(key_bytes, TRUE);
    return status;
}

/* UAT record post update callback */
static void
uat_key_record_post_update_cb(void)
{
    return;
}

/* @dissectors@ */

static void
dissect_cmd_command_class_security_v1(tvbuff_t *tvb, proto_tree *tree, guint8 cmd_length, guint8 offset, packet_info *pinfo, guint8 src_id, guint8 dst_id)
{
    proto_item *cmd_ti = 0;
    cmd_ti = proto_tree_add_item(tree, hf_command_class_security_v1, tvb, offset, 1, ENC_NA);
    cmd_length--;
    guint cmd = tvb_get_guint8(tvb, offset++);
    guint8 minimal_length;

    guint8 *nonce = NULL;
    recv_nonce_t *recv_nonce = NULL;
    guint8 *enc_data = NULL;
    guint8 *dec_data = NULL;
    guint8 *mac = NULL;
    guint enc_len = 0;
    sec0_dec_status_t dec_status = DEC_OK;
    const gchar *dec_status_text;
    proto_tree *dec_tree;

    const gchar *cmd_string = val_to_str_const(cmd, zwave_command_class_security_v1_commands,  "%s");

    if (strncmp(cmd_string, "%s", 2) == 0) {
        // Unknown command
        cmd_string = "Unknown CMD";
    }

    col_add_fstr(pinfo->cinfo, COL_INFO, "%s", cmd_string );

    switch(cmd)
    {
    case COMMAND_CLASS_SECURITY_V1_NETWORK_KEY_SET:
        minimal_length = 0;
        if (cmd_length < minimal_length){
            break;
        }
        cmd_ti = proto_tree_add_item(tree, hf_command_class_security_v1_network_key_set_network_key_byte, tvb, offset, cmd_length - offset + 2, ENC_NA);
        offset += cmd_length - minimal_length;
        break;
    
    
    case COMMAND_CLASS_SECURITY_V1_SECURITY_COMMANDS_SUPPORTED_REPORT:
        minimal_length = 2;
        if (cmd_length < minimal_length){
            break;
        }
        cmd_ti = proto_tree_add_item(tree, hf_command_class_security_v1_security_commands_supported_report_reports_to_follow, tvb, offset, 1, ENC_NA);
        offset += 1;
        cmd_ti = proto_tree_add_item(tree, hf_command_class_security_v1_security_commands_supported_report_command_class_support, tvb, offset, tvb_find_guint8(tvb, offset, -1, 0xef) - offset , ENC_NA);
        offset += tvb_find_guint8(tvb, offset, -1, 0xef) - offset;
        cmd_ti = proto_tree_add_item(tree, hf_command_class_security_v1_security_commands_supported_report_command_class_mark, tvb, offset, 1, ENC_NA);
        offset += 1;
        cmd_ti = proto_tree_add_item(tree, hf_command_class_security_v1_security_commands_supported_report_command_class_control, tvb, offset, cmd_length - offset + 2, ENC_NA);
        break;
    case COMMAND_CLASS_SECURITY_V1_SECURITY_MESSAGE_ENCAPSULATION:
        minimal_length = 18;
        if (cmd_length < minimal_length){
            break;
        }
        cmd_ti = proto_tree_add_item(tree, hf_command_class_security_v1_security_message_encapsulation_initialization_vector_byte, tvb, offset, 8, ENC_NA);
        offset += 8;

        // Try to decrypt data
        enc_len = (cmd_length - minimal_length) + 1;
        nonce = (guint8 *)wmem_alloc(wmem_packet_scope(), ZWAVE_SEC0_NONCE_LENGTH);
        enc_data = (guint8 *)wmem_alloc(wmem_packet_scope(), enc_len);
        dec_data = (guint8 *)wmem_alloc(wmem_packet_scope(), enc_len);
        mac = (guint8 *)wmem_alloc(wmem_packet_scope(), ZWAVE_SEC0_MAC_LENGTH);

        tvb_memcpy(tvb, nonce, offset-ZWAVE_SEC0_NONCE_LENGTH, ZWAVE_SEC0_NONCE_LENGTH);
        tvb_memcpy(tvb, enc_data, offset, enc_len);
        tvb_memcpy(tvb, mac, offset + cmd_length - minimal_length + 2, ZWAVE_SEC0_MAC_LENGTH);

        dec_status = zwave_sec0_decrypt(enc_data, enc_len, nonce, tvb_get_guint8(tvb, offset+enc_len), pinfo->num, dec_data, mac, src_id, dst_id);

        cmd_ti = proto_tree_add_item(tree, hf_command_class_security_v1_security_message_encapsulation_properties1, tvb, offset, 1, ENC_NA);
        offset += 1;
        cmd_ti = proto_tree_add_item(tree, hf_command_class_security_v1_security_message_encapsulation_command_byte, tvb, offset, cmd_length - minimal_length, ENC_NA);

        // Add decryption subtree
        dec_tree = proto_item_add_subtree(cmd_ti, ett_zwave_sec0_decrypted);

        // Display decryption status
        dec_status_text = val_to_str_const(dec_status, zwave_sec0_dec_status,  "%s");
        if (strncmp(dec_status_text, "%s", 2) == 0) {
            // Return value not in list
            dec_status_text = "Unknown";
        }
        proto_tree_add_text_internal(dec_tree, tvb, offset, enc_len-1, "[Decryption status: %s]", dec_status_text);

        // Display decrypted data
        if (dec_status >= DEC_OK) {
            proto_tree_add_text_internal(dec_tree, tvb, offset, enc_len-1, "[Decrypted Data]");

            tvbuff_t *dec_tvb = tvb_new_child_real_data(tvb, dec_data+1, enc_len-1, enc_len);
            dissect_cmd_class(dec_tvb, pinfo, dec_tree, enc_len-1, 0, src_id, dst_id);
        }

        offset += cmd_length - minimal_length;
        cmd_ti = proto_tree_add_item(tree, hf_command_class_security_v1_security_message_encapsulation_receivers_nonce_identifier, tvb, offset, 1, ENC_NA);
        offset += 1;
        cmd_ti = proto_tree_add_item(tree, hf_command_class_security_v1_security_message_encapsulation_message_authentication_code_byte, tvb, offset, 8, ENC_NA);

        // Display MAC validation status
        if (dec_status == DEC_OK_MAC_VALID) {
            proto_tree_add_text_internal(tree, tvb, offset, 8, "[MAC status: Valid]");
        } else if (dec_status == DEC_OK_MAC_INVALID) {
            proto_tree_add_text_internal(tree, tvb, offset, 8, "[MAC status: Invalid]");
        } else {
            proto_tree_add_text_internal(tree, tvb, offset, 8, "[MAC status: Unchecked]");
        }

        offset += 8;
        break;
    case COMMAND_CLASS_SECURITY_V1_SECURITY_MESSAGE_ENCAPSULATION_NONCE_GET:
        minimal_length = 18;
        if (cmd_length < minimal_length){
            break;
        }
        cmd_ti = proto_tree_add_item(tree, hf_command_class_security_v1_security_message_encapsulation_nonce_get_initialization_vector_byte, tvb, offset, 8, ENC_NA);
        offset += 8;
        cmd_ti = proto_tree_add_bitmask_text(tree, tvb, offset, 1, "Properties1", NULL, command_class_security_v1_security_message_encapsulation_nonce_get_properties1_subtree, command_class_security_v1_security_message_encapsulation_nonce_get_properties1_structbyte_fields ,ENC_BIG_ENDIAN, 0);
        offset += 1;
        cmd_ti = proto_tree_add_item(tree, hf_command_class_security_v1_security_message_encapsulation_nonce_get_command_byte, tvb, offset, cmd_length - minimal_length, ENC_NA);
        offset += cmd_length - minimal_length;
        cmd_ti = proto_tree_add_item(tree, hf_command_class_security_v1_security_message_encapsulation_nonce_get_receivers_nonce_identifier, tvb, offset, 1, ENC_NA);
        offset += 1;
        cmd_ti = proto_tree_add_item(tree, hf_command_class_security_v1_security_message_encapsulation_nonce_get_message_authentication_code_byte, tvb, offset, 8, ENC_NA);
        offset += 8;
        break;
    
    case COMMAND_CLASS_SECURITY_V1_SECURITY_NONCE_REPORT:
        minimal_length = 0;
        cmd_ti = proto_tree_add_item(tree, hf_command_class_security_v1_security_nonce_report_nonce_byte, tvb, offset, cmd_length - offset + 2, ENC_NA);

        recv_nonce = (recv_nonce_t *)wmem_alloc(NULL, sizeof(recv_nonce_t));
        tvb_memcpy(tvb, recv_nonce->nonce, offset, ZWAVE_SEC0_NONCE_LENGTH);
        recv_nonce->frame_num = pinfo->num;

        zwave_sec0_register_nonce(recv_nonce);
        wmem_free(NULL, recv_nonce);
        offset += cmd_length;

        offset += cmd_length - minimal_length;
        break;
    case COMMAND_CLASS_SECURITY_V1_SECURITY_SCHEME_GET:
        minimal_length = 1;
        if (cmd_length < minimal_length){
            break;
        }
        cmd_ti = proto_tree_add_item(tree, hf_command_class_security_v1_security_scheme_get_supported_security_schemes, tvb, offset, 1, ENC_NA);
        offset += 1;
        break;
    case COMMAND_CLASS_SECURITY_V1_SECURITY_SCHEME_INHERIT:
        minimal_length = 1;
        if (cmd_length < minimal_length){
            break;
        }
        cmd_ti = proto_tree_add_item(tree, hf_command_class_security_v1_security_scheme_inherit_supported_security_schemes, tvb, offset, 1, ENC_NA);
        offset += 1;
        break;
    case COMMAND_CLASS_SECURITY_V1_SECURITY_SCHEME_REPORT:
        minimal_length = 1;
        if (cmd_length < minimal_length){
            break;
        }
        cmd_ti = proto_tree_add_item(tree, hf_command_class_security_v1_security_scheme_report_supported_security_schemes, tvb, offset, 1, ENC_NA);
        offset += 1;
        break;
    default:
        break;
    }
    cmd_ti = cmd_ti + 0;
}


void
dissect_cmd_class (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint8 remaining_length, guint8 offset, guint8 src_id,
        guint8 dst_id)
{
    proto_item *cmd_ti = 0;
    guint8 cmd_class = tvb_get_guint8(tvb, offset);

    const gchar *cmd_class_string = val_to_str_const(cmd_class, zwave_cmd_classes,  "%s");

    if (strncmp(cmd_class_string, "%s", 2) == 0)
    {
        // Unknown command class
        cmd_class_string = "Unknown";
    }

    cmd_ti = proto_tree_add_subtree_format(tree, tvb, offset, remaining_length, 0, 0, "Command Class: %s", cmd_class_string);
    proto_tree *cmd_class_tree = proto_item_add_subtree(cmd_ti, ett_zwave_cmd_class);

    cmd_ti = proto_tree_add_item(cmd_class_tree, hf_zwave_generic_cmd_class, tvb, offset, 1, ENC_NA);
    remaining_length--;
    offset++;

    if (remaining_length < 1){
        return;
    }

    switch (cmd_class) {
    case COMMAND_CLASS_SECURITY_V1:
        dissect_cmd_command_class_security_v1(tvb, cmd_class_tree, remaining_length, offset, pinfo, src_id, dst_id);
        break;

/* @dissect_cmd_switch_case@ */
    }

    pinfo++;
}


static guint8
calc_xor_cs(tvbuff_t *tvb)
{
    guint8 cs = 0xFF;
    for (guint byte_idx = 0; byte_idx < tvb_captured_length(tvb)-sizeof(cs); byte_idx++) {
        cs ^= tvb_get_guint8(tvb, byte_idx);
    }

    return cs;
}

static guint16
calc_crc16_cs(tvbuff_t *tvb)
{
    guint data_len = tvb_captured_length(tvb) - sizeof(guint16);
    guint8 *data = (guint8 *)wmem_alloc(wmem_packet_scope(), data_len);
    tvb_memcpy(tvb, data, 0, data_len);
    return crc16_x25_ccitt_seed(data, data_len, CRC16_SEED);
}

/* Code to actually dissect the packets */
static int
dissect_zwave(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
    void *data _U_, zwave_pdu_type pdu_type)
{
    proto_item *ti, *expert_ti;
    proto_tree *zwave_tree;
    zwave_hdr_r1_r2 zwhdr;
    guint8 frame_type = 0;
    gint offset = 0;
    char *frame_str = "Unknown MPDU";

    /*** HEURISTICS ***/

    /* Check that the packet is long enough for it to belong to zwave. */
    if (tvb_reported_length(tvb) < ZWAVE_MIN_LENGTH) {
        return 0;
    }

    /*** Check and validate PDU type ***/
    if (pdu_type == PDU_TYPE_UNKNOWN) {
        if (calc_xor_cs(tvb) == tvb_get_guint8(tvb, -1)) {
            pdu_type = PDU_TYPE_R1_R2;
        } else if (calc_crc16_cs(tvb) == tvb_get_ntohs(tvb, -2)) {
            pdu_type = PDU_TYPE_R3;
        } else {
            // fprintf(stderr, "Unable to determine PDU type. Defaulting to R3\n");
            pdu_type = PDU_TYPE_R3;
        }
    }

    /*** COLUMN DATA ***/

    /* Get values and fill structure */
    zwhdr.home_id = tvb_get_ntohl(tvb, 0);
    zwhdr.src_id = tvb_get_guint8(tvb, 4);
    zwhdr.frame_ctrl = tvb_get_guint8(tvb, 5);
    zwhdr.seq = tvb_get_guint8(tvb, 6);
    zwhdr.len = tvb_get_guint8(tvb, 7);
    zwhdr.dst_id = tvb_get_guint8(tvb, 8);

    /* Set the Protocol column to zwave */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "Z-Wave");

    /* Set Info column */
    frame_type = (zwhdr.frame_ctrl & 0x0F);
    switch (frame_type)
    {
        case ZWAVE_SINGLECAST_MPDU:
            frame_str = "Singlecast";
            break;
        case ZWAVE_MULTICAST_MPDU:
            frame_str = "Multicast";
            break;
        case ZWAVE_ACKNOWLEDGE_MPDU:
            frame_str = "Acknowledgement";
            break;
        case ZWAVE_ROUTER_MPDU:
            frame_str = "Router MPDU";
            break;
    }
    col_add_fstr(pinfo->cinfo, COL_INFO, "Z-Wave %s", frame_str);

    /* Set Src/Dst columns */
    col_add_fstr(pinfo->cinfo, COL_DEF_SRC, "0x%02x", tvb_get_guint8(tvb, 4));
    col_add_fstr(pinfo->cinfo, COL_DEF_DST, "0x%02x", tvb_get_guint8(tvb, 8));

    /*** PROTOCOL TREE ***/

    /* Now we will create a sub-tree for our protocol and start adding fields
     * to display under that sub-tree. Most of the time the only functions you
     * will need are proto_tree_add_item() and proto_item_add_subtree().
     *
     * NOTE: The offset and length values in the call to proto_tree_add_item()
     * define what data bytes to highlight in the hex display window when the
     * line in the protocol tree display corresponding to that item is selected.
     *
     * Supplying a length of -1 tells Wireshark to highlight all data from the
     * offset to the end of the packet.
     */

    /* create display subtree for the protocol */
    ti = proto_tree_add_protocol_format(tree, proto_zwave, tvb, 0, -1,
                                        "Z-Wave, Src: 0x%02x, Dst: 0x%02x",
                                        tvb_get_guint8(tvb, 4), tvb_get_guint8(tvb, 8));

    zwave_tree = proto_item_add_subtree(ti, ett_zwave);

    /* Add items to subtree*/
    ti = proto_tree_add_item(zwave_tree, hf_zwave_home_id, tvb, 0, 4, ENC_NA);
    ti = proto_tree_add_item(zwave_tree, hf_zwave_src, tvb, 4, 1, ENC_NA);

    /* frame_ctrl subtree */
    ti = proto_tree_add_item(zwave_tree, hf_zwave_frame_ctrl, tvb, 5, 1, ENC_NA);
    proto_tree *frame_ctrl_tree = proto_item_add_subtree(ti, ett_zwave_frame_ctrl);
    ti = proto_tree_add_boolean(frame_ctrl_tree, hf_zwave_routed, tvb, 40, 1, zwhdr.frame_ctrl);
    ti = proto_tree_add_boolean(frame_ctrl_tree, hf_zwave_ack_req, tvb, 41, 1, zwhdr.frame_ctrl);
    ti = proto_tree_add_boolean(frame_ctrl_tree, hf_zwave_low_pwr, tvb, 42, 1, zwhdr.frame_ctrl);
    ti = proto_tree_add_boolean(frame_ctrl_tree, hf_zwave_speed_mod, tvb, 43, 1, zwhdr.frame_ctrl);
    ti = proto_tree_add_bits_item(frame_ctrl_tree, hf_zwave_frame_type, tvb, 44, 4, ENC_NA);

    ti = proto_tree_add_item(zwave_tree, hf_zwave_seq, tvb, 6, 1, ENC_NA);

    ti = proto_tree_add_item(zwave_tree, hf_zwave_len, tvb, 7, 1, ENC_NA);
    ti = proto_tree_add_item(zwave_tree, hf_zwave_dst, tvb, 8, 1, ENC_NA);

    offset = 9;
    tvbuff_t *cmd_class_tvb = tvb_new_subset_length_caplen(tvb, offset, tvb_captured_length(tvb) - pdu_type - 9, -1);

    if (frame_type != ZWAVE_ACKNOWLEDGE_MPDU) {
        dissect_cmd_class(cmd_class_tvb, pinfo, zwave_tree, tvb_captured_length(tvb) - pdu_type - 9, 0, zwhdr.src_id, zwhdr.dst_id);
    }

    /* Add Checksum and checksum status */
    if (pdu_type == PDU_TYPE_R1_R2) {
        ti = proto_tree_add_checksum(zwave_tree, tvb, zwhdr.len-1, hf_zwave_checksum_r1_r2, hf_zwave_checksum_status,
                NULL, pinfo, calc_xor_cs(tvb), ENC_BIG_ENDIAN, PROTO_CHECKSUM_VERIFY);
    } else if (pdu_type == PDU_TYPE_R3) {
        ti = proto_tree_add_checksum(zwave_tree, tvb, zwhdr.len-2, hf_zwave_checksum_r3, hf_zwave_checksum_status,
                NULL, pinfo, calc_crc16_cs(tvb), ENC_BIG_ENDIAN, PROTO_CHECKSUM_VERIFY);
    }

    /* Some fields or situations may require "expert" analysis that can be
     * specifically highlighted. */
    if (0)
        /* value of hf_zwave_sample_field isn't what's expected */
        expert_add_info(pinfo, expert_ti, &ei_zwave_expert);

    /* Continue adding tree items to process the packet here... */

    /* If this protocol has a sub-dissector call it here, see section 1.8 of
     * README.dissector for more information. */

    /* Return the amount of data this dissector was able to dissect (which may
     * or may not be the total captured packet as we return here). */
    return tvb_captured_length(tvb);
}

static int
dissect_zwave_generic(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
    void *data _U_)
{
    return dissect_zwave(tvb, pinfo, tree, data, PDU_TYPE_UNKNOWN);
}

/* Register the protocol with Wireshark.
 *
 * This format is required because a script is used to build the C function that
 * calls all the protocol registration.
 */
void
proto_register_zwave(void)
{
    module_t *prefs_module;
    expert_module_t *expert_zwave;

    /* Setup list of header fields  See Section 1.5 of README.dissector for
     * details. */
    static hf_register_info hf[] = {
        {&hf_zwave_home_id,
         {"Home ID", "zwave.home_id",
          FT_UINT32, BASE_HEX, NULL, 0x0,
          NULL, HFILL}},

        {&hf_zwave_src,
         {"Source Node ID", "zwave.src",
          FT_UINT8, BASE_HEX, NULL, 0x0,
          NULL, HFILL}},

        {&hf_zwave_frame_ctrl,
         {"Frame Control", "zwave.frame_ctrl",
          FT_UINT8, BASE_HEX, NULL, 0x0,
          NULL, HFILL}},

        {&hf_zwave_routed,
         {"Routed", "zwave.routed",
          FT_BOOLEAN, 8, NULL, 0x80,
          NULL, HFILL}},

        {&hf_zwave_ack_req,
         {"Acknowledgement Requested", "zwave.ack_req",
          FT_BOOLEAN, 8, NULL, 0x40,
          NULL, HFILL}},

        {&hf_zwave_low_pwr,
         {"Low Power", "zwave.low_pwr",
          FT_BOOLEAN, 8, NULL, 0x20,
          NULL, HFILL}},

        {&hf_zwave_speed_mod,
         {"Speed Modified", "zwave.ack_req",
          FT_BOOLEAN, 8, NULL, 0x10,
          NULL, HFILL}},

        {&hf_zwave_frame_type,
         {"Frame Type", "zwave.frame_type",
          FT_UINT8, BASE_HEX, VALS(zwave_frame_types), 0x0,
          NULL, HFILL}},

        {&hf_zwave_seq,
         {"Sequence Number", "zwave.seq",
          FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL}},

        {&hf_zwave_len,
         {"Package length", "zwave.len",
          FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL}},

        {&hf_zwave_dst,
         {"Destination Node ID", "zwave.dst",
          FT_UINT8, BASE_HEX, NULL, 0x0,
          NULL, HFILL}},

        {&hf_zwave_checksum_r1_r2,
         {"Checksum", "zwave.checksum",
          FT_UINT8, BASE_HEX, NULL, 0x0,
          NULL, HFILL}},

        {&hf_zwave_checksum_r3,
         {"Checksum", "zwave.checksum",
          FT_UINT16, BASE_HEX, NULL, 0x0,
          NULL, HFILL}},

        {&hf_zwave_checksum_status,
         {"Checksum status", "zwave.checksum.status",
          FT_UINT8, BASE_NONE, VALS(proto_checksum_vals), 0x0,
          NULL, HFILL}},

        {&hf_zwave_generic_cmd_class,
         {"Command Class", "zwave.cc",
          FT_UINT8, BASE_HEX, VALS(zwave_cmd_classes), 0x0,
          NULL, HFILL}},

        {&hf_command_class_security_v1,
          {"Command", "zwave.command_class_security_v1",
          FT_UINT8, BASE_HEX, VALS(zwave_command_class_security_v1_commands), 0x0,
          NULL, HFILL}},

        {&hf_command_class_security_v1_network_key_set_network_key_byte,
          {"Network Key Byte", "zwave.command_class_security_v1_network_key_set_network_key_byte",
          FT_BYTES, BASE_NONE, NULL, 0x0,
          NULL, HFILL}},

        {&hf_command_class_security_v1_security_commands_supported_report_reports_to_follow,
          {"Reports To Follow", "zwave.command_class_security_v1_security_commands_supported_report_reports_to_follow",
          FT_UINT8, BASE_HEX, NULL, 0x0,
          NULL, HFILL}},

        {&hf_command_class_security_v1_security_commands_supported_report_command_class_support,
          {"Command Class Support", "zwave.command_class_security_v1_security_commands_supported_report_command_class_support",
          FT_BYTES, BASE_NONE, NULL, 0x0,
          NULL, HFILL}},

        {&hf_command_class_security_v1_security_commands_supported_report_command_class_mark,
          {"Command_Class_Mark", "zwave.command_class_security_v1_security_commands_supported_report_command_class_mark",
          FT_UINT8, BASE_HEX, NULL, 0x0,
          NULL, HFILL}},

        {&hf_command_class_security_v1_security_commands_supported_report_command_class_control,
          {"Command Class Control", "zwave.command_class_security_v1_security_commands_supported_report_command_class_control",
          FT_BYTES, BASE_NONE, NULL, 0x0,
          NULL, HFILL}},

        {&hf_command_class_security_v1_security_message_encapsulation_initialization_vector_byte,
          {"Initialization Vector Byte", "zwave.command_class_security_v1_security_message_encapsulation_initialization_vector_byte",
          FT_BYTES, BASE_NONE, NULL, 0x0,
          NULL, HFILL}},

        {&hf_command_class_security_v1_security_message_encapsulation_properties1,
          {"Properties1", "zwave.hf_command_class_security_v1_security_message_encapsulation_properties1",
          FT_UINT8, BASE_HEX, NULL, 0,
          NULL, HFILL}},

        {&hf_command_class_security_v1_security_message_encapsulation_command_byte,
          {"Command Byte [Encrypted]", "zwave.command_class_security_v1_security_message_encapsulation_command_byte",
          FT_BYTES, BASE_NONE, NULL, 0x0,
          NULL, HFILL}},

        {&hf_command_class_security_v1_security_message_encapsulation_receivers_nonce_identifier,
          {"Receivers Nonce Identifier", "zwave.command_class_security_v1_security_message_encapsulation_receivers_nonce_identifier",
          FT_UINT8, BASE_HEX, NULL, 0x0,
          NULL, HFILL}},

        {&hf_command_class_security_v1_security_message_encapsulation_message_authentication_code_byte,
          {"Message Authentication Code Byte", "zwave.command_class_security_v1_security_message_encapsulation_message_authentication_code_byte",
          FT_BYTES, BASE_NONE, NULL, 0x0,
          NULL, HFILL}},

        {&hf_command_class_security_v1_security_message_encapsulation_nonce_get_initialization_vector_byte,
          {"Initialization Vector Byte", "zwave.command_class_security_v1_security_message_encapsulation_nonce_get_initialization_vector_byte",
          FT_BYTES, BASE_NONE, NULL, 0x0,
          NULL, HFILL}},

        {&hf_command_class_security_v1_security_message_encapsulation_nonce_get_properties1,
          {"Properties1", "zwave.hf_command_class_security_v1_security_message_encapsulation_nonce_get_properties1",
          FT_UINT8, BASE_HEX, NULL, 0,
          NULL, HFILL}},


        {&hf_command_class_security_v1_security_message_encapsulation_nonce_get_properties1_bitflag_sequenced,
          {" Sequenced", "zwave.hf_command_class_security_v1_security_message_encapsulation_nonce_get_properties1_bitflag_sequenced",
          FT_BOOLEAN, 8, NULL, 0x10,
          NULL, HFILL}},


        {&hf_command_class_security_v1_security_message_encapsulation_nonce_get_properties1_bitflag_secondframe,
          {" Second Frame", "zwave.hf_command_class_security_v1_security_message_encapsulation_nonce_get_properties1_bitflag_secondframe",
          FT_BOOLEAN, 8, NULL, 0x20,
          NULL, HFILL}},


        {&hf_command_class_security_v1_security_message_encapsulation_nonce_get_properties1_bitfield_sequencecounter,
          {" Sequence Counter", "zwave.hf_command_class_security_v1_security_message_encapsulation_nonce_get_properties1_bitfield_sequencecounter",
          FT_UINT8, BASE_HEX, NULL, 0x0F,
          NULL, HFILL}},


        {&hf_command_class_security_v1_security_message_encapsulation_nonce_get_properties1_bitfield_reserved,
          {" Reserved", "zwave.hf_command_class_security_v1_security_message_encapsulation_nonce_get_properties1_bitfield_reserved",
          FT_UINT8, BASE_HEX, NULL, 0xC0,
          NULL, HFILL}},

        {&hf_command_class_security_v1_security_message_encapsulation_nonce_get_command_byte,
          {"Command Byte", "zwave.command_class_security_v1_security_message_encapsulation_nonce_get_command_byte",
          FT_BYTES, BASE_NONE, NULL, 0x0,
          NULL, HFILL}},

        {&hf_command_class_security_v1_security_message_encapsulation_nonce_get_receivers_nonce_identifier,
          {"Receivers Nonce Identifier", "zwave.command_class_security_v1_security_message_encapsulation_nonce_get_receivers_nonce_identifier",
          FT_UINT8, BASE_HEX, NULL, 0x0,
          NULL, HFILL}},

        {&hf_command_class_security_v1_security_message_encapsulation_nonce_get_message_authentication_code_byte,
          {"Message Authentication Code Byte", "zwave.command_class_security_v1_security_message_encapsulation_nonce_get_message_authentication_code_byte",
          FT_BYTES, BASE_NONE, NULL, 0x0,
          NULL, HFILL}},

        {&hf_command_class_security_v1_security_nonce_report_nonce_byte,
          {"Nonce Byte", "zwave.command_class_security_v1_security_nonce_report_nonce_byte",
          FT_BYTES, BASE_NONE, NULL, 0x0,
          NULL, HFILL}},

        {&hf_command_class_security_v1_security_scheme_get_supported_security_schemes,
          {"Supported Security Schemes", "zwave.command_class_security_v1_security_scheme_get_supported_security_schemes",
          FT_UINT8, BASE_HEX, NULL, 0x0,
          NULL, HFILL}},

        {&hf_command_class_security_v1_security_scheme_inherit_supported_security_schemes,
          {"Supported Security Schemes", "zwave.command_class_security_v1_security_scheme_inherit_supported_security_schemes",
          FT_UINT8, BASE_HEX, NULL, 0x0,
          NULL, HFILL}},

        {&hf_command_class_security_v1_security_scheme_report_supported_security_schemes,
          {"Supported Security Schemes", "zwave.command_class_security_v1_security_scheme_report_supported_security_schemes",
          FT_UINT8, BASE_HEX, NULL, 0x0,
          NULL, HFILL}},

/* @registered_headerfields@ */
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_zwave,
        &ett_zwave_frame_ctrl,
        &ett_zwave_cmd_class,
        &ett_zwave_sec0_decrypted,
        &command_class_security_v1_security_message_encapsulation_nonce_get_properties1_subtree,

/* @subtree_entries@ */
    };

    /* Setup protocol expert items */
    static ei_register_info ei[] = {
        {&ei_zwave_expert,
         {"zwave.expert", PI_PROTOCOL, PI_ERROR,
          "EXPERTDESCR", EXPFILL}}};

    /* Register the protocol name and description */
    proto_zwave = proto_register_protocol("Z-Wave",
                                          "Z-Wave", "zwave");

    /* Required function calls to register the header fields and subtrees */
    proto_register_field_array(proto_zwave, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Required function calls to register expert items */
    expert_zwave = expert_register_protocol(proto_zwave);
    expert_register_field_array(expert_zwave, ei, array_length(ei));

    /* Register a preferences module for user defined keys */
    static uat_field_t key_uat_fields[] = {
        UAT_FLD_CSTRING(zwave_sec0_uat_key_records, string, "Network Key", "A 16-Byte key."),
        UAT_END_FIELDS
    };

    prefs_module = prefs_register_protocol(proto_zwave, prefs_zwave_apply);
    zwave_sec0_key_table_uat = uat_new("Z-Wave Security 0 Network Keys", sizeof(uat_key_record_t), "zwave_sec0_keys", TRUE,
            &zwave_sec0_uat_key_records, &num_uat_key_records, UAT_AFFECTS_DISSECTION, NULL, uat_key_record_copy_cb,
            uat_key_record_update_cb, uat_key_record_free_cb, uat_key_record_post_update_cb, NULL, key_uat_fields);

    prefs_register_uat_preference(prefs_module, "sec0_network_keys", "Security 0 Network Keys",
            "Security 0 Network Keys", zwave_sec0_key_table_uat);

    zwave_sec0_init();
}

void
proto_reg_handoff_zwave(void)
{
    static gboolean initialized = FALSE;
    static dissector_handle_t zwave_handle;

    if (!initialized)
    {
        /* Use create_dissector_handle() to indicate that
         * dissect_zwave() returns the number of bytes it dissected (or 0
         * if it thinks the packet does not belong to Z-Wave).
         */
        zwave_handle = create_dissector_handle(dissect_zwave_generic, proto_zwave);
        initialized = TRUE;
    }
    else
    {
        /* If you perform registration functions which are dependent upon
         * prefs then you should de-register everything which was associated
         * with the previous settings and re-register using the new prefs
         * settings here. In general this means you need to keep track of
         * the zwave_handle and the value the preference had at the time
         * you registered.  The zwave_handle value and the value of the
         * preference can be saved using local statics in this
         * function (proto_reg_handoff).
         */
        // dissector_delete_uint("tcp.port", current_port, zwave_handle);
    }
    dissector_add_uint("wtap_encap", WTAP_ENCAP_USER0, zwave_handle);
}

void
prefs_zwave_apply(void)
{
    return;
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
