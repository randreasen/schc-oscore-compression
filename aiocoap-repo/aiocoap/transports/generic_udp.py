# This file is part of the Python aiocoap library project.
#
# Copyright (c) 2012-2014 Maciej Wasilak <http://sixpinetrees.blogspot.com/>,
#               2013-2014 Christian Amsüss <c.amsuess@energyharvesting.at>
#
# aiocoap is free software, this file is published under the MIT license as
# described in the accompanying LICENSE file.

import asyncio
import urllib

from aiocoap import interfaces, error
from aiocoap import COAP_PORT, Message

class GenericTransportEndpoint(interfaces.TransportEndpoint):
    """GenericTransportEndpoint is not a standalone implementation of a
    transport. It does implement everything between the TransportEndpoint
    interface and a not yet fully specified interface of "bound UDP
    sockets"."""

    def __init__(self, ctx: interfaces.MessageManager, log, loop):
        self._ctx = ctx
        self._log = log
        self._loop = loop

    async def determine_remote(self, request):
        if request.requested_scheme not in ('coap', None):
            return None

        if request.unresolved_remote is not None:
            pseudoparsed = urllib.parse.SplitResult(None, request.unresolved_remote, None, None, None)
            host = pseudoparsed.hostname
            port = pseudoparsed.port or COAP_PORT
        elif request.opt.uri_host:
            host = request.opt.uri_host
            port = request.opt.uri_port or COAP_PORT
        else:
            raise ValueError("No location found to send message to (neither in .opt.uri_host nor in .remote)")

        return await self._pool.connect((host, port))

    def _received_datagram(self, address, datagram):
        try:
            message = Message.decode(datagram, remote=address)
        except error.UnparsableMessage:
            self._log.warning("Ignoring unparsable message from %s"%(address,))
            return

        self._ctx.dispatch_message(message)

    def _received_exception(self, address, exception):
        self._ctx.dispatch_error(exception.errno, address)

    def send(self, message):
        message.remote.send(message.encode())

    async def shutdown(self):
        await self._pool.shutdown()
        self._ctx = None
