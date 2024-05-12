/* packet-zwave.h
 *
 * Wireshark - Network traffic analyzer
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_ZWAVE_H__
#define __PACKET_ZWAVE_H__

#include "ws_symbol_export.h"
#include "packet-zwave-sec0-decrypt.h"

/*
 * Z-Wave MAC Header Types
 */
#define ZWAVE_SINGLECAST_MPDU       1
#define ZWAVE_MULTICAST_MPDU        2
#define ZWAVE_ACKNOWLEDGE_MPDU      3
#define ZWAVE_ROUTER_MPDU           8

typedef struct _zwave_hdr_r1_r2 {
    guint32 home_id;
    guint8  src_id;
    guint8  frame_ctrl;
    guint8  seq;
    guint8  len;
    guint8  dst_id;
} zwave_hdr_r1_r2;


#endif /* __PACKET_ZWAVE_H__ */
