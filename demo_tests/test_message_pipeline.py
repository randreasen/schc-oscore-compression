from binascii import hexlify
import copy
import shutil
import os
from aiocoap.message import Message
from aiocoap.oscore import piv2os, piv2payload
from schcoscore import SchcOSCORE, Pipeline
import pytest

class MockOptions:
    def __init__(self, **kwargs):
        self.d = dict(**kwargs)

    def __getattr__(self, key):
        return self.d[key]

@pytest.fixture
def oscore_dir():
    directory = "myoscore_dir"
    if os.path.exists(directory):
        shutil.rmtree(directory)
    os.mkdir(directory)
    yield directory
    shutil.rmtree(directory)


def test_pipeline_get_message(oscore_dir):
    program = Pipeline(
        opts=MockOptions(code='GET',
                         dump_inner=True,
                         mid='1',
                         mtype='CON',
                         no_inner_compression=False,
                         no_oscore=False,
                         no_outer_compression=False,
                         no_piv2payload=False,
                         oscore_dir='myoscore_dir',
                         payload=None,
                         role=None,
                         silent=False,
                         token='0x82',
                         # uri='coap://localhost/temperature',
                         uri='coap://127.0.0.1/temperature',
                         uri_path=None,
                         verbose=True,
                         with_dump=True,
                         )
    )

    results = program.run()
    [msg, protected, compressed, decompressed, decrypted] = results.as_list()

    def hex_dump(m):
        return hexlify(m.encode())

    print("msg:")
    print(hex_dump(msg))
    print("protected:")
    print(hex_dump(protected))
    print("compressed:")
    print(hex_dump(compressed))
    print("decompressed:")
    print(hex_dump(decompressed))
    print("decrypted:")
    print(hex_dump(decrypted))

    assert hex_dump(decompressed) == hex_dump(protected)
    assert hex_dump(decrypted) == hex_dump(msg)

    assert(hex_dump(msg) == b'4101000182bb74656d7065726174757265')
    assert(hex_dump(protected.opt) == b'd70809636c69656e74')

    # 4 bits sent -> mid (mid length = 16 bits, 12 msb masked)
    # 3 bits sent -> token (token length = 8 bits, 5 msb masked)

    compressed_bytes = compressed.encode()

    assert compressed_bytes[0] == 0x00 # RuleID
    assert (compressed_bytes[1] & 0xF0) >> 4 == 1 # mid
    assert (compressed_bytes[1] & 0b1110) >> 1 == 2 # token

    compressed_payload = compressed_bytes[2:]
    n_bytes = len(compressed_payload)
    compressed_payload = int.from_bytes(compressed_payload, byteorder='big') >> 1 # since padding = 1
    compressed_payload = compressed_payload.to_bytes(n_bytes, byteorder='big')
    lead = compressed_payload[0] + ((compressed_bytes[1] & 0b0001) << 7) # 7 since 8 - padding = 7
    compressed_payload = bytes([lead, *compressed_payload[1:]])

    assert compressed_payload == protected.payload

    assert SchcOSCORE.compareMsgs(msg, decrypted)


def test_pipeline_rfc_example_get_message(oscore_dir):
    program = Pipeline(
        opts=MockOptions(code='GET',
                         dump_inner=True,
                         mid='1',
                         mtype='CON',
                         no_inner_compression=False,
                         no_oscore=False,
                         no_outer_compression=False,
                         no_piv2payload=False,
                         oscore_dir='myoscore_dir',
                         payload=None,
                         role=None,
                         silent=False,
                         token='0x82',
                         # uri='coap://localhost/temperature',
                         uri=None,
                         uri_path='temperature',
                         verbose=True,
                         with_dump=True,
                         )
    )

    results = program.run()
    [msg, protected, compressed, decompressed, decrypted] = results.as_list()

    def hex_dump(m):
        return hexlify(m.encode())

    print("msg:")
    print(hex_dump(msg))
    print("protected:")
    print(hex_dump(protected))
    print("compressed:")
    print(hex_dump(compressed))
    print("decompressed:")
    print(hex_dump(decompressed))
    print("decrypted:")
    print(hex_dump(decrypted))

    assert hex_dump(decompressed) == hex_dump(protected)
    assert hex_dump(decrypted) == hex_dump(msg)

    assert(hex_dump(msg) == b'4101000182bb74656d7065726174757265')
    assert(hex_dump(protected.opt) == b'd70809636c69656e74')

    compressed_bytes = compressed.encode()

    assert compressed_bytes[0] == 0x00 # RuleID
    assert (compressed_bytes[1] & 0xF0) >> 4 == 1 # mid
    assert (compressed_bytes[1] & 0b1110) >> 1 == 2 # token

    compressed_payload = compressed_bytes[2:]
    n_bytes = len(compressed_payload)
    compressed_payload = int.from_bytes(compressed_payload, byteorder='big') >> 1 # since padding = 1
    compressed_payload = compressed_payload.to_bytes(n_bytes, byteorder='big')
    lead = compressed_payload[0] + ((compressed_bytes[1] & 0b0001) << 7) # 7 since 8 - padding = 7
    compressed_payload = bytes([lead, *compressed_payload[1:]])

    assert compressed_payload == protected.payload

    assert hex_dump(msg) == b'4101000182bb74656d7065726174757265'

    protected_without_payload = copy.deepcopy(protected)
    protected_without_payload.payload = b''

    assert hex_dump(protected_without_payload) == b'4102000182d70809636c69656e74'
    assert compressed.encode()[:2] == b'\x00\x14'

    decompressed_without_payload = copy.deepcopy(decompressed)
    decompressed_without_payload.payload = b''

    assert hex_dump(decompressed_without_payload) == b'4102000182d70809636c69656e74'
    assert hex_dump(decrypted) == b'4101000182bb74656d7065726174757265'

    assert SchcOSCORE.compareMsgs(msg, decrypted)


def test_pipeline_post_message(oscore_dir):

    # First run the GET request
    Pipeline(
        opts=MockOptions(code='GET',
                         dump_inner=True,
                         mid='1',
                         mtype='CON',
                         no_inner_compression=False,
                         no_oscore=False,
                         no_outer_compression=False,
                         no_piv2payload=False,
                         oscore_dir='myoscore_dir',
                         payload=None,
                         role=None,
                         silent=False,
                         token='0x82',
                         # uri='coap://localhost/temperature',
                         uri='coap://127.0.0.1/temperature',
                         uri_path=None,
                         verbose=True,
                         with_dump=True,
                         )
    ).run()

    # And now run the response
    program = Pipeline(
        opts=MockOptions(
            code='CONTENT',
            dump_inner=False,
            mid='1',
            mtype='ACK',
            no_inner_compression=False,
            no_oscore=False,
            no_outer_compression=False,
            no_piv2payload=False,
            oscore_dir='myoscore_dir',
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

    results = program.run()

    assert SchcOSCORE.compareMsgs(results.message, results.decrypted)
