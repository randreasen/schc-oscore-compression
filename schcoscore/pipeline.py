import binascii
import socket

from aiocoap import Message, OptionNumber
from aiocoap.transports.udp6 import UDP6EndpointAddress
from aiocoap.numbers.types import Type as message_types
import aiocoap.numbers.codes as codes

from .common import AbstractMessage, SchcOSCORE
from .utils import debug_dump_message


class PipelineResults:
        MESSAGE_ATTRS=("message",
                       "protected",
                       "compressed",
                       "decompressed",
                       "decrypted")

        def __init__(self,
                     message: AbstractMessage,
                     protected: AbstractMessage,
                     compressed: AbstractMessage,
                     decompressed: AbstractMessage,
                     decrypted: AbstractMessage,
                     inner_dump=None,
                     opts=None):
                self.message = message
                self.protected = protected
                self.compressed = compressed
                self.decompressed = decompressed
                self.decrypted = decrypted
                self.inner_dump = inner_dump
                self.opts = opts

        def as_list(self):
                return [getattr(self, attr) for attr in self.MESSAGE_ATTRS]


class Pipeline:
        def __init__(self, opts=None):
                self.opts = opts
                self.schc_oscore = SchcOSCORE(oscoredir=self.opts.oscore_dir)
                self.inner_dump = None
                self.has_piv = False

        @staticmethod
        def create_option(name: str, value):
                opt = getattr(OptionNumber, name)
                return opt.create_option(value=value)

        def build_message(self, opts):
                if opts.uri_path and opts.uri:
                        raise ValueError("Both URI and URI-Path cannot be specified at the same time")

                role = opts.role or "client"

                msg = Message(
                        mtype=message_types[opts.mtype],
                        mid=int(opts.mid, 16),
                        code=getattr(codes.Code, opts.code),
                        token=binascii.a2b_hex("{:02x}".format(int(opts.token, 16))),
                )

                if opts.uri is not None:
                        msg.set_request_uri(opts.uri)

                if opts.uri_path is not None:
                        msg.opt.add_option(self.create_option("URI_PATH", opts.uri_path))

                if opts.payload is not None:
                        msg.payload = binascii.unhexlify(opts.payload)

                msg.remote = UDP6EndpointAddress(
                        socket.getaddrinfo(
                                '127.0.0.1',
                                5683,
                                type=socket.SOCK_DGRAM,
                                family=socket.AF_INET6,
                                flags=socket.AI_V4MAPPED
                        )[0][-1]
                )

                return msg, role

        def protect_message(self, msg, role) -> AbstractMessage:
                protected_msg, has_piv, inner_dump = self.schc_oscore.encrypt(
                        msg,
                        role,
                        piv2payload=not self.opts.no_piv2payload,
                        compress_inner=not self.opts.no_inner_compression,
                        dump_inner=self.opts.dump_inner,
                )
                self.inner_dump = inner_dump
                self.has_piv = has_piv
                return protected_msg

        def compress_outer_message(self, msg, role) -> AbstractMessage:
                return self.schc_oscore.compress_outer(msg, direction="up" if role == "client" else "dw")

        def decompress_outer_message(self, msg, role) -> AbstractMessage:
                return self.schc_oscore.decompress_outer(msg, direction="up" if role == "client" else "dw")

        def unprotect_message(self, msg, role) -> AbstractMessage:
                return self.schc_oscore.decrypt(
                        msg,
                        role,
                        piv2payload=not self.opts.no_piv2payload,
                        compress_inner=not self.opts.no_inner_compression,
                        has_piv=self.has_piv,
                )

        def run(self):
                msg, role = self.build_message(self.opts)

                debug_dump_message(msg, "original")

                if self.opts.no_oscore:
                        protected_msg = msg
                else:
                        protected_msg = self.protect_message(msg, role)

                debug_dump_message(protected_msg, "protected_msg")

                if self.opts.no_outer_compression:
                        compressed_msg = protected_msg
                else:
                        compressed_msg = self.compress_outer_message(protected_msg, role)

                debug_dump_message(compressed_msg, "compressed_msg")

                if self.opts.no_outer_compression:
                        decompressed_msg = Message.decode(compressed_msg.encode())
                else:
                        decompressed_msg = self.decompress_outer_message(compressed_msg, role)

                debug_dump_message(decompressed_msg, "decompressed_msg")

                if not self.opts.no_oscore:
                        decrypted_msg = self.unprotect_message(decompressed_msg, role)
                else:
                        decrypted_msg = decompressed_msg

                debug_dump_message(decrypted_msg, "decrypted_msg")

                return PipelineResults(
                        msg,
                        protected_msg,
                        compressed_msg,
                        decompressed_msg,
                        decrypted_msg,
                        inner_dump=self.inner_dump,
                        opts=self.opts,
                )
