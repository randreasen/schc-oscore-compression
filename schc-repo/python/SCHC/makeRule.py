# Script that writes the SCHC rule into a json format that
# can be read by the rest of the program.
#
# USE: Edit the rule table, then run the script. It will
# automatically affect the relevant files.

import json
import os
import pprint

inner_rules = []
outer_rules = []
# To be properly filled:
#                           fID                Pos   DI   TV                    MO           CDA
INNER_GET_TEMP_WITH_FF = { \
            "name": "INNER_GET_TEMP_WITH_FF",
            "ruleid"  : 3,
            "content" : [["CoAP.code",          1,  "up", 1,                  "equal", "not-sent"],
                         ["CoAP.code",          1,  "dw", [69, 132],          "match-mapping", "mapping-sent"],
                         ["CoAP.Uri-Path",      1,  "up", "temperature",          "equal", "not-sent"],
                         ["CoAP.Option-End",    1,  "dw", 0xFF,               "equal", "not-sent"]
                        ]}


INNER_GET_TEMP_NO_FF = { \
            "name": "INNER_GET_TEMP_NO_FF",
            "ruleid"  : 4,
            "content" : [["CoAP.code",          1,  "up", 1,                  "equal", "not-sent"],
                         ["CoAP.code",          1,  "dw", [69, 132],          "match-mapping", "mapping-sent"],
                         ["CoAP.Uri-Path",      1,  "bi", "temperature",          "equal", "not-sent"],
                        ]}


INNER_GET_MEASUREMENT_WITH_FF = { \
            "name": "INNER_GET_MEASUREMENT_WITH_FF",
            "ruleid"  : 5,
            "content" : [["CoAP.code",          1,  "up", 1,                  "equal", "not-sent"],
                         ["CoAP.code",          1,  "dw", [69, 132],          "match-mapping", "mapping-sent"],
                         ["CoAP.Uri-Path",      1,  "up", "measurement",          "equal", "not-sent"],
                         ["CoAP.Option-End",    1,  "dw", 0xFF,               "equal", "not-sent"]
                        ]}

inner_rules.append(INNER_GET_TEMP_WITH_FF)
inner_rules.append(INNER_GET_TEMP_NO_FF)
inner_rules.append(INNER_GET_MEASUREMENT_WITH_FF)

OUTER_PROTECTED = {"ruleid"  : 0,
             "name": "OUTER_PROTECTED",
             "content" : [["IPv6.version",      1,  "bi", 6,                  "equal",  "not-sent"],
                          ["IPv6.trafficClass", 1,  "bi", 0x00,               "equal",  "not-sent"],
                          ["IPv6.flowLabel",    1,  "bi", 0x000000,            "equal",  "not-sent"],
                          ["IPv6.payloadLength",1,  "bi", None,               "ignore", "compute-length"],
                          ["IPv6.nextHeader",   1,  "bi", 17,                 "equal",  "not-sent"],
                          ["IPv6.hopLimit",     1,  "bi", 30,                 "ignore", "not-sent"],
                          ["IPv6.prefixES",     1,  "bi", 0xFE80000000000000, "equal", "not-sent"],
                          ["IPv6.iidES",        1,  "bi", 0x0000000000000001, "equal", "not-sent"],
                          ["IPv6.prefixLA",     1,  "bi", 0xFE80000000000000, "equal", "not-sent"],
                          ["IPv6.iidLA",        1,  "bi", 0x0000000000000002, "equal", "not-sent"],
                          ["UDP.PortES",        1,  "bi", 5682,               "equal", "not-sent"],
                          ["UDP.PortLA",        1,  "bi", 5683,               "equal", "not-sent"],
                          ["UDP.length",        1,  "bi", None,               "ignore", "compute-length"],
                          ["UDP.checksum",      1,  "bi", None,               "ignore", "compute-checksum"],
                          ["CoAP.version",      1,  "bi", 1,                  "equal", "not-sent"],
                          ["CoAP.type",         1,  "up", 0,                  "equal", "not-sent"],
                          ["CoAP.type",         1,  "dw", 2,                  "equal", "not-sent"],
                          ["CoAP.tokenLength",  1,  "bi", 1,                  "equal", "not-sent"],
                          ["CoAP.code",         1,  "up", 2,                  "equal", "not-sent"],
                          ["CoAP.code",         1,  "dw", 68,                  "equal", "not-sent"],
                          ["CoAP.messageID",    1,  "bi", 0,                  "MSB(12)", "LSB"],
                          ["CoAP.token",        1,  "bi", 0x80,               "MSB(5)", "LSB"],
                          ["CoAP.Object-Security",1, "up", "\tclient",         "equal", "not-sent"],
                          ["CoAP.Object-Security",1, "dw", "",         "equal", "not-sent"],
                          ["CoAP.Option-End",   1,  "bi", 0xFF,               "equal", "not-sent"]
                       ]}

OUTER_NO_OSCORE = {"ruleid"  : 1,
             "name": "OUTER_NO_OSCORE",
             "content" : [["IPv6.version",      1,  "bi", 6,                  "equal",  "not-sent"],
                          ["IPv6.trafficClass", 1,  "bi", 0x00,               "equal",  "not-sent"],
                          ["IPv6.flowLabel",    1,  "bi", 0x000000,            "equal",  "not-sent"],
                          ["IPv6.payloadLength",1,  "bi", None,               "ignore", "compute-length"],
                          ["IPv6.nextHeader",   1,  "bi", 17,                 "equal",  "not-sent"],
                          ["IPv6.hopLimit",     1,  "bi", 30,                 "ignore", "not-sent"],
                          ["IPv6.prefixES",     1,  "bi", 0xFE80000000000000, "equal", "not-sent"],
                          ["IPv6.iidES",        1,  "bi", 0x0000000000000001, "equal", "not-sent"],
                          ["IPv6.prefixLA",     1,  "bi", 0xFE80000000000000, "equal", "not-sent"],
                          ["IPv6.iidLA",        1,  "bi", 0x0000000000000002, "equal", "not-sent"],
                          ["UDP.PortES",        1,  "bi", 5682,               "equal", "not-sent"],
                          ["UDP.PortLA",        1,  "bi", 5683,               "equal", "not-sent"],
                          ["UDP.length",        1,  "bi", None,               "ignore", "compute-length"],
                          ["UDP.checksum",      1,  "bi", None,               "ignore", "compute-checksum"],
                          ["CoAP.version",      1,  "bi", 1,                  "equal", "not-sent"],
                          ["CoAP.type",         1,  "up", 0,                  "equal", "not-sent"],
                          ["CoAP.type",         1,  "dw", 2,                  "equal", "not-sent"],
                          ["CoAP.tokenLength",  1,  "bi", 1,                  "equal", "not-sent"],
                          ["CoAP.code",         1,  "up", 1,                  "equal", "not-sent"],
                          ["CoAP.code",         1,  "dw", [69, 132],          "match-mapping", "mapping-sent"],
                          ["CoAP.messageID",    1,  "bi", 0,                  "MSB(12)", "LSB"],
                          ["CoAP.token",        1,  "bi", 0x80,               "MSB(5)", "LSB"],
                          ["CoAP.Uri-Path",     1,  "up", "temperature",      "equal", "not-sent"],
                          ["CoAP.Option-End",   1,  "dw", 0xFF,               "equal", "not-sent"]
                       ]}

outer_rules.append(OUTER_PROTECTED)
outer_rules.append(OUTER_NO_OSCORE)

encoded = json.dumps(inner_rules)
filename = "myrule.inner"

with open(os.path.join(".", filename), "w") as out:
	json.dump(encoded,out)

print("Successfully wrote to {}".format(os.path.join(".", filename)))
pp = pprint.PrettyPrinter(indent=4)
print("Written rules were:")
for elem in inner_rules:
	pp.pprint(elem)

encoded = json.dumps(outer_rules)
filename = "myrule.outer"

with open(os.path.join(".", filename), "w") as out:
	json.dump(encoded,out)

print("Successfully wrote to {}".format(os.path.join(".", filename)))
pp = pprint.PrettyPrinter(indent=4)
print("Written rules were:")
for elem in outer_rules:
	pp.pprint(elem)
