from typing import Union
from binascii import hexlify, unhexlify

import aiocoap

from schcoscore import Pipeline


def decode_message(encoded: Union[str, bytes, int]):
    if isinstance(encoded, int):
        msg_str = "{:x}".format(encoded)
        return decode_message(msg_str)

    elif isinstance(encoded, str):
        if encoded.startswith("0x"):
            encoded = encoded[2:]
        msg_bytes = unhexlify(encoded)
        return decode_message(msg_bytes)

    elif isinstance(encoded, bytes):
        msg = aiocoap.Message.decode(encoded)
        return msg

    else:
        raise TypeError(
            "Unexpected type for encoded message: {}. Should be str, bytes or int.".format(
            type(encoded)
            )
        )


def test_decode_message():
    hex_str = "0x6145000182ff32332043"

    reencoded_str = "0x" + (hexlify(
                                decode_message(hex_str)
                                .encode()
                            )
                            .decode(
                                "ascii"
                            )
                            )

    assert hex_str == reencoded_str

    hex_int = 0x6145000182ff32332043

    reencoded_int = int(hexlify(
                            decode_message(hex_int)
                            .encode()
                        )
                        .decode("ascii"),
                        16)
    
    assert hex_int == reencoded_int

    hex_bytes = b"aE\x00\x01\x82\xff23 C"

    reencoded_bytes = (decode_message(hex_bytes)
                       .encode())

    assert reencoded_bytes == hex_bytes

class MockOptions:
    def __init__(self, **kwargs):
        self.d = dict(**kwargs)

    def __getattr__(self, key):
        return self.d[key]

def test_build_get_message():
    program = Pipeline(
        MockOptions(code='GET',
                    dump_inner=False,
                    mid='1',
                    mtype='CON',
                    no_inner_compression=False,
                    no_oscore=False,
                    no_outer_compression=False,
                    no_piv2payload=False,
                    oscore_dir='oscore_dir',
                    payload=None,
                    role=None,
                    silent=False,
                    token='0x82',
                    uri='coap://localhost/temperature',
                    uri_path=None,
                    verbose=True,
                    with_dump=True,
                    )
    )

    msg, role = program.build_message(program.opts)

    msg_hex = hexlify(msg.encode()).decode("ascii")

    assert msg_hex == "4101000182396c6f63616c686f73748b74656d7065726174757265"
    assert role == "client"



def test_build_post_message():
    program = Pipeline(
        MockOptions(code='CONTENT',
                    dump_inner=False,
                    mid='1',
                    mtype='ACK',
                    no_inner_compression=False,
                    no_oscore=False,
                    no_outer_compression=False,
                    no_piv2payload=False,
                    oscore_dir='oscore_dir',
                    payload=None,
                    role='server',
                    silent=False,
                    token='0x82',
                    uri=None,
                    uri_path='temperature',
                    verbose=True,
                    with_dump=True,
                    )
    )

    msg, role = program.build_message(program.opts)

    msg_hex = hexlify(msg.encode()).decode("ascii")

    assert msg_hex == "6145000182bb74656d7065726174757265"
    assert role == "server"


def test_build_message_with_payload():
    program = Pipeline(
        MockOptions(code='POST',
                    dump_inner=False,
                    mid='1',
                    mtype='CON',
                    no_inner_compression=False,
                    no_oscore=False,
                    no_outer_compression=False,
                    no_piv2payload=False,
                    oscore_dir=None,
                    payload='48656c6c6f',
                    role=None,
                    silent=False,
                    token='0x82',
                    uri=None,
                    uri_path='coap://localhost/measure',
                    verbose=True,
                    with_dump=False,
                    )
    )

    msg, role = program.build_message(program.opts)

    msg_hex = hexlify(msg.encode()).decode("ascii")

    assert msg_hex == "4102000182bd0b636f61703a2f2f6c6f63616c686f73742f6d656173757265ff48656c6c6f"
    assert role == "client"
