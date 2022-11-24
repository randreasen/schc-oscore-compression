import json
import binascii
import tempfile
import os
import struct
import cbor

from aiocoap import oscore

from schc.RuleMngt import RuleManager
from schc.Parser_fused import Parser
from schc.Compressor import Compressor
from schc.Decompressor import Decompressor

from typing import Union
from aiocoap import Message

class SCHCCompressedMessage:
        def __init__(self, compressed_msg: bytes):
                self.compressed_msg = compressed_msg

        def encode(self) -> bytes:
                return self.compressed_msg


AbstractMessage = Union[Message, SCHCCompressedMessage]

from . import log
logger = log.getLogger("logger")

class SchcOSCORE:
        def __init__(self, oscoredir=None):
                self.clientSecctx = self.mkFileSystemSecurityContext(role="client", directory=oscoredir)
                self.serverSecctx = self.mkFileSystemSecurityContext(role="server", directory=oscoredir)

                schcRule_outer = json.loads(json.load(open(os.path.join(".", "schc", "myrule.outer"))))
                self.RM_outer = RuleManager()
                for elem in schcRule_outer:
                        self.RM_outer.addRule(elem)

                self.parser_outer = Parser()
                self.comp_outer = Compressor(self.RM_outer)
                self.dec_outer  = Decompressor(self.RM_outer)

                self.IPv6_source = binascii.unhexlify("FE80:0000:0000:0000:0000:0000:0000:0001".replace (':', ''))
                self.IPv6_dest   = binascii.unhexlify("FE80:0000:0000:0000:0000:0000:0000:0002".replace (':', ''))

        @staticmethod
        def mkFileSystemSecurityContext(role, directory=None):

                def floadncopy(filename):
                        with open(os.path.join(contextdir, filename), "rt") as f:
                                filedata = json.load(f)
                        with open(os.path.join(contextcopy, filename), "w") as out:
                                json.dump(filedata, out)

                        return filedata

                SEQNO = 0

                contextdir = 'oscore-common-context'

                if directory is None:
                        os.makedirs('temp-contexts', exist_ok=True)
                        contextcopy= tempfile.mkdtemp(prefix='context-', dir='temp-contexts')
                else:
                        contextcopy = os.path.join(directory, role)
                        os.makedirs(contextcopy, exist_ok=True)

                secretdata = floadncopy("secret.json")
                settingsdata = floadncopy("settings.json")

                if not os.path.exists(os.path.join(contextcopy, "sequence.json")):
                        sequence = {
                        "used": {(settingsdata['server-sender-id_hex'] if role == 'server' else settingsdata['client-sender-id_hex']).lower(): SEQNO},
                        "seen": {(settingsdata['client-sender-id_hex'] if role == 'server' else settingsdata['server-sender-id_hex']).lower(): list([SEQNO - 1]) if role == 'server' else [-1]}
                        }

                        with open(os.path.join(contextcopy, "sequence.json"), "w") as out:
                                json.dump(sequence, out)

                return oscore.FilesystemSecurityContext(contextcopy, role=role)

        @staticmethod
        def IP_UDP(ips, ipd, ps, pd, ulp ):

                IP_buffer = struct.pack ( '!HHHBB', 0x6000, 0x0000, len( ulp ) + 8, 17, 30 ) + \
                ips + \
                ipd + \
                struct.pack ( "!HHHH", ps, pd, len( ulp ) + 8, 0x0000 ) + \
                ulp

                return IP_buffer

        @staticmethod
        def ctx_from_token(token, secctx):
                if os.path.exists(os.path.join(secctx.basedir, "request_info.cbor")):
                        all_requests = cbor.load(open(os.path.join(secctx.basedir, "request_info.cbor"), "rb"))
                else:
                        raise FileNotFoundError("Could not find request_info.cbor with request context")
                request = None
                for elem in all_requests:
                        if elem["token"] == token:
                                request = elem
                                break

                if request is None:
                        raise ValueError("No recorded Security Context matching this Token: {}".format(token))

                with open(os.path.join(secctx.basedir, "request_info.cbor"), "wb") as out:
                        cbor.dump(all_requests, out)
                return request["kid"], request["piv"], request["nonce"]

        def encrypt(self, msg, role, piv2payload=True, compress_inner=True, dump_inner=False):
                if role == "client":
                        secctx = self.clientSecctx
                elif role == "server":
                        secctx = self.serverSecctx
                else:
                        raise ValueError("Invalid role: must be either client or server")

                request_data = None
                if msg.code.is_response():
                        request_data = self.ctx_from_token(msg.token, secctx)

                inner_dump = None

                if dump_inner:
                        protected_msg, original_request_seqno, inner_dump = secctx.protect(
                                msg,
                                compress_inner=compress_inner,
                                direction="up" if role == "client" else "dw",
                                request_data=request_data,
                                dump_inner=dump_inner,
                        )
                else:
                        protected_msg, original_request_seqno = secctx.protect(
                                msg,
                                compress_inner=compress_inner,
                                direction="up" if role == "client" else "dw",
                                request_data=request_data,
                                dump_inner=dump_inner,
                        )

                secctx._store()

                if msg.code.is_request():
                        request_info = {
                                "token": msg.token,
                                "kid": original_request_seqno[0],
                                "piv": original_request_seqno[1],
                                "nonce": original_request_seqno[2]
                        }

                        if os.path.exists(os.path.join(secctx.basedir, "request_info.cbor")):
                                all_requests = cbor.load(open(os.path.join(secctx.basedir, "request_info.cbor"), "rb"))
                        else:
                                all_requests = []

                        all_requests.append(request_info)

                        with open(os.path.join(secctx.basedir, "request_info.cbor"), "wb") as out:
                                cbor.dump(all_requests, out)

                protected_msg.mtype = msg.mtype   # Some unprotected fields that are not
                protected_msg.mid = msg.mid       # handled by the encryption 
                protected_msg.token = msg.token

                if piv2payload:
                        protected_msg, has_piv = oscore.piv2payload(protected_msg)
                else:
                        has_piv = False

                return protected_msg, has_piv, inner_dump

        def compress_outer(self, msg, direction="up"):
                logger.debug("compress_outer: Got encoded message:")
                logger.debug(msg.encode())
                logger.debug("compress_outer: pprinted msg:")
                for line in log.pprint_s(msg).splitlines():
                        logger.debug(line)

                IPv6 = self.IP_UDP(self.IPv6_source, self.IPv6_dest, 5682, 5683, msg.encode())

                fields, data = self.parser_outer.parser(IPv6)
                rule = self.comp_outer.RuleMngt.FindRuleFromHeader(fields, direction)
                result = None

                if rule is None:
                        raise ValueError(
                                "No matching rule (dir = {}) found for fields: {}"
                                .format(direction, fields)
                        )


                result = struct.pack('!B', rule["ruleid"]) # start with the ruleid
                res = self.comp_outer.apply(fields, rule["content"], "%s" % direction)
                if data is not None:
                        res.add_bytes(data)
                        result += res.buffer()
                return SCHCCompressedMessage(result)

        def decompress_outer(self, msg, direction="up"):
                msg = msg.encode()

                respRuleId = msg[0:1] # First byte is ruleid
                respResidue = msg[1:] # The rest is the compression residue

                decRule = self.dec_outer.RuleMngt.FindRuleFromID(respRuleId[0])
                if decRule is None:
                        raise ValueError("No rule found for message")
                else:
                        respPkt, respPktLength = self.dec_outer.apply(respResidue, decRule, "%s" % direction)

                        IPv6Header = respPkt [0:40]
                        UDPHeader = respPkt [40:48]
                        CoAPresp = respPkt[48:]
                decompressed = Message.decode(CoAPresp)
                decompressed.payload = bytes(decompressed.payload)
                decompressed.token = bytes(decompressed.token)
                return decompressed

        def decrypt(self, msg, role, piv2payload=True, compress_inner=True, has_piv=True):
                if piv2payload and has_piv:
                        msg = oscore.piv2os(msg)

                if role == "client":
                        secctx = self.serverSecctx
                elif role == "server":
                        secctx = self.clientSecctx
                else:
                        raise ValueError("Invalid role: must be either client or server")

                if msg.code.is_request():
                        recipient_id = oscore.verify_start(msg)
                        if recipient_id != secctx.recipient_id:
                                raise ValueError("Recipient ID doesn't match that of the Security Context")

                request_data = None
                if msg.code.is_response():
                        request_data = self.ctx_from_token(msg.token, secctx)

                        logger.debug("decrypt: Got request_data from context:")
                        logger.debug(request_data)

                unprotected, seqno = secctx.unprotect(
                        msg,
                        decompress_inner=compress_inner,
                        direction="up" if role == "client" else "dw",
                        request_data=request_data,
                )

                if msg.code.is_request():
                        request_info = {
                                "token": msg.token,
                                "kid": seqno[0],
                                "piv": seqno[1],
                                "nonce": seqno[2]
                        }

                        if os.path.exists(os.path.join(secctx.basedir, "request_info.cbor")):
                                all_requests = cbor.load(open(os.path.join(secctx.basedir, "request_info.cbor"), "rb"))
                        else:
                                all_requests = []

                        all_requests.append(request_info)

                        with open(os.path.join(secctx.basedir, "request_info.cbor"), "wb") as out:
                                cbor.dump(all_requests, out)

                unprotected.mtype = msg.mtype
                unprotected.mid = msg.mid
                unprotected.token = msg.token

                secctx._store()
                return unprotected

        @staticmethod
        def compareMsgs(msg1, msg2):
                return msg1.encode() == msg2.encode()
