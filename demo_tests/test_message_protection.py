from binascii import hexlify, unhexlify
import socket

from aiocoap.message import Message
from aiocoap.transports.udp6 import UDP6EndpointAddress

from schc.RuleMngt import RuleManager

from schcoscore import AbstractMessage, SchcOSCORE

import pytest

@pytest.fixture()
def client_context():
    return SchcOSCORE.mkFileSystemSecurityContext("client")
    

@pytest.fixture()
def server_context():
    return SchcOSCORE.mkFileSystemSecurityContext("server")

def hex_dump(msg: AbstractMessage):
    return hexlify(msg.encode())


INNER_SCHC_RULE = {
    "name": "INNER_GET_TEMP_NO_FF",
    "ruleid"  : 4,
    "content" : [
        ["CoAP.code",          1,  "up", 1,                  "equal", "not-sent"],
        ["CoAP.code",          1,  "dw", [69, 132],          "match-mapping", "mapping-sent"],
        ["CoAP.Uri-Path",      1,  "bi", "temperature",          "equal", "not-sent"],
    ]
}


@pytest.fixture()
def schc_inner_compressor():
    manager = RuleManager()
    manager.addRule(INNER_SCHC_RULE)
    

def message_from_hex(hex: bytes):
    return Message.decode(unhexlify(hex))


def test_message_protection(client_context, schc_inner_compressor):

    msg = message_from_hex(b'4101000182bb74656d7065726174757265')


    msg.remote = UDP6EndpointAddress(
        socket.getaddrinfo(
            '127.0.0.1',
            5683,
            type=socket.SOCK_DGRAM,
            family=socket.AF_INET6,
            flags=socket.AI_V4MAPPED
        )[0][-1]
    )

    role = "client"

    (protected_msg,
     original_request_seqno,
     inner_dump) = client_context.protect(msg, compress_inner=True,
                                          direction="up" if role == "client" else "dw",
                                          request_data=None,
                                          dump_inner=True)


    protected_msg.mtype = msg.mtype   # Some unprotected fields that are not
    protected_msg.mid = msg.mid       # ("properly") handled by the encryption 
    protected_msg.token = msg.token

    print("Protected message dump:")
    hex_dump(protected_msg)

    print("Inner dump:")
    print(inner_dump)

    # import pdb
    # pdb.set_trace()

    print("Finished test")

