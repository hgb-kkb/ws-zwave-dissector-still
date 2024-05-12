#!/usr/bin/env python3
#
# make-usb - Creates a file containing vendor and product ids.
# It use the databases from
# https://usb-ids.gowdy.us/
# to create our file epan/dissectors/usb.c
#
# It also uses the values culled out of libgphoto2 using usb-ptp-extract-models.pl

import re
import sys
import urllib.request, urllib.error, urllib.parse

MODE_IDLE           = 0
MODE_VENDOR_PRODUCT = 1
MIN_VENDORS = 3400 # 3409 as of 2020-11-15
MIN_PRODUCTS = 20000 # 20361 as of 2020-11-15

mode = MODE_IDLE

# The canonical location for the usb.ids file is http://www.linux-usb.org/usb.ids.
# As of November 2020 that site isn't available over HTTPS. Use what appears to
# be the source code repository for the site.
req_headers = { 'User-Agent': 'Wireshark make-usb' }
req = urllib.request.Request('https://sourceforge.net/p/linux-usb/repo/HEAD/tree/trunk/htdocs/usb.ids?format=raw', headers=req_headers)
response = urllib.request.urlopen(req)
lines = response.read().decode('UTF-8', 'replace').splitlines()

vendors  = dict()
products = dict()
vendors_str="static const value_string usb_vendors_vals[] = {\n"
products_str="static const value_string usb_products_vals[] = {\n"

# Escape backslashes, quotes, control characters and non-ASCII characters.
escapes = {}
for i in range(256):
    if i in b'\\"':
        escapes[i] = '\\%c' % i
    elif i in range(0x20, 0x80) or i in b'\t':
        escapes[i] = chr(i)
    else:
        escapes[i] = '\\%03o' % i

for utf8line in lines:
    # Convert single backslashes to double (escaped) backslashes, escape quotes, etc.
    utf8line = utf8line.rstrip()
    utf8line = re.sub("\?+", "?", utf8line)
    line = ''.join(escapes[byte] for byte in utf8line.encode('utf8'))

    if line == "# Vendors, devices and interfaces. Please keep sorted.":
        mode = MODE_VENDOR_PRODUCT
        continue
    elif line == "# List of known device classes, subclasses and protocols":
        mode = MODE_IDLE
        continue

    if mode == MODE_VENDOR_PRODUCT:
        if re.match("^[0-9a-f]{4}", line):
            last_vendor=line[:4]
            vendors[last_vendor] = line[4:].strip()
        elif re.match("^\t[0-9a-f]{4}", line):
            line = line.strip()
            product = "%s%s"%(last_vendor, line[:4])
            products[product] = line[4:].strip()


# Grab from libgphoto (indirectly through tools/usb-ptp-extract-models.pl)
u = open('tools/usb-ptp-extract-models.txt','r')
for line in u.readlines():
    fields=line.split()
    products[fields[0]]= ' '.join(fields[1:])

if (len(vendors) < MIN_VENDORS):
    sys.stderr.write("Not enough vendors: %d\n" % len(vendors))
    sys.exit(1)

if (len(products) < MIN_PRODUCTS):
    sys.stderr.write("Not enough products: %d\n" % len(products))
    sys.exit(1)

for v in sorted(vendors):
    vendors_str += "    { 0x%s, \"%s\" },\n"%(v,vendors[v])

vendors_str += """    { 0, NULL }\n};
value_string_ext ext_usb_vendors_vals = VALUE_STRING_EXT_INIT(usb_vendors_vals);
"""

for p in sorted(products):
    products_str += "    { 0x%s, \"%s\" },\n"%(p,products[p])

products_str += """    { 0, NULL }\n};
value_string_ext ext_usb_products_vals = VALUE_STRING_EXT_INIT(usb_products_vals);
"""

header="""/* usb.c
 * USB vendor id and product ids
 * This file was generated by running python ./tools/make-usb.py
 * Don't change it directly.
 *
 * Copyright 2012, Michal Labedzki for Tieto Corporation
 *
 * Other values imported from libghoto2/camlibs/ptp2/library.c, music-players.h
 *
 * Copyright (C) 2001-2005 Mariusz Woloszyn <emsi@ipartners.pl>
 * Copyright (C) 2003-2013 Marcus Meissner <marcus@jet.franken.de>
 * Copyright (C) 2005 Hubert Figuiere <hfiguiere@teaser.fr>
 * Copyright (C) 2009 Axel Waggershauser <awagger@web.de>
 * Copyright (C) 2005-2007 Richard A. Low <richard@wentnet.com>
 * Copyright (C) 2005-2012 Linus Walleij <triad@df.lth.se>
 * Copyright (C) 2007 Ted Bullock
 * Copyright (C) 2012 Sony Mobile Communications AB
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * XXX We should probably parse a USB ID file at program start instead
 * of generating this file.
 */

#include "config.h"
#include <epan/packet.h>
"""

f = open('epan/dissectors/usb.c', 'w')
f.write(header)
f.write("\n")
f.write(vendors_str)
f.write("\n\n")
f.write(products_str)
f.write("\n")
f.close()

print("Success!")