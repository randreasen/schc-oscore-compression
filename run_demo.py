#!/usr/bin/env python3
from aiocoap import *
from aiocoap import oscore

import argparse

import schcoscore
from schcoscore import SchcOSCORE

import schcoscore.log as log
logger = log.getLogger("logger")

def parse_arguments():
        p = argparse.ArgumentParser("SCHC-OSCORE testing program...")
        arguments = [
                ("--mtype",                              "CoAP Message Type"),
                ("--code",                               "CoAP Message Code"),
                ("--token",                              "CoAP message Token (hex string)"),
                ("--mid",                                "CoAP Message ID"),
                ("--uri",                                "Full URI to be parsed into its component CoAP options"),
                ("--uri-path",                           "CoAP Message URI-Path"),
                ("--payload",                            "CoAP Message Payload"),
                ("--role",                               "Role for OSCORE protection"),
                ("--oscore-dir",                         "Persistent directory to store OSCORE Context information"),
                ("--verbose",              "store_true", "Output Message information"),
                ("--no-oscore",            "store_true", "Disables OSCORE protection"),
                ("--no-piv2payload",       "store_true", "Leaves the piv in the Object-Security option, which"
                                                         "defers from draft specification but is default aiocoap"
                                                         "behaviour."),
                ("--no-outer-compression", "store_true", "Disables outer SCHC compression"),
                ("--no-inner-compression", "store_true", "Disables inner SCHC compression"),
                ("--with-dump",            "store_true", "Gives a dump of each intermediate message as they are"
                                                         "generated"),
                ("--silent",               "store_true", "Removes the usual output, so that only the explicitly "
                                                         "requested output can be easily piped into another program"),
                ("--dump-inner",           "store_true", "Dump includes inner OSCORE plaintext once it has been compressed")
        ]
        for arg in arguments:
                if len(arg) == 2:
                        name, description = arg
                        p.add_argument(name, help=description)
                elif len(arg) == 3:
                        name, action, description = arg
                        p.add_argument(name, action=action, help=description)
                else:
                        ValueError("Wrong format for argument: {}".format(arg))
        return p.parse_args()
        

if __name__ == "__main__":
        results = schcoscore.Pipeline(parse_arguments()).run()

        [msg, protected, compressed, decompressed, decrypted] = results.as_list()

        verbose = results.opts.verbose
        silent = results.opts.silent
        with_dump = results.opts.with_dump
        no_oscore = results.opts.no_oscore
        inner_dump = results.inner_dump
        no_outer_compression = results.opts.no_outer_compression

        if verbose:
                print("Original msg:     {}".format(msg.encode()))
                print("Protected msg:    {}".format(protected.encode()))
                print("Compressed msg:   {}".format(compressed.encode()))
                print("Decompressed msg: {}".format(decompressed.encode()))
                print("Decrypted msg:    {}".format(decrypted.encode()))

                print("-----------------------------------------------------")

                print("Original msg:     {}".format(msg.encode().hex()))
                print("Protected msg:    {}".format(protected.encode().hex()))
                print("Compressed msg:   {}".format(compressed.encode().hex()))
                print("Decompressed msg: {}".format(decompressed.encode().hex()))
                print("Decrypted msg:    {}".format(decrypted.encode().hex()))

        if SchcOSCORE.compareMsgs(msg,decrypted):
                if not silent:
                        print("Successful decryption")
        else:
                raise oscore.DecodeError("Decryption failed")

        if not silent:

                print("Original msg length:   {}".format(len(msg.encode())))
                print("Protected msg length:  {}".format(len(protected.encode())))
                print("Compressed msg length: {}".format(len(compressed.encode())))
                print("End-to-end msg length factor: {:2.2f}%".format(len(compressed.encode())/len(msg.encode())*100))

        if with_dump:
                print("\nOriginal message:")
                print("=================")
                schcoscore.MsgDump(msg).decompressed_dump()
                if not no_oscore:
                        if inner_dump is not None:
                                print("\nOSCORE Plaintext:")
                                print("==================")
                                print(inner_dump[0])
                                print("\nCompressed Plaintext:")
                                print("======================")
                                print(inner_dump[1])
                        print("\nProtected message:")
                        print("==================")
                        schcoscore.MsgDump(protected).decompressed_dump()
                if not no_outer_compression:
                        print("\nCompressed message:")
                        print("==================")
                        schcoscore.MsgDump(compressed).compressed_dump(protected.payload)
