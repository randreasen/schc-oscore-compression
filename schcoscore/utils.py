import json
import binascii

from aiocoap.options import Options
from .common import AbstractMessage

from . import log
logger = log.getLogger("logger")

def serialize_json(obj):
        try:
                if isinstance(obj, Options):
                        return obj.encode()
                return obj.toJSON()
        except AttributeError:
                return str(obj)

def pprint_message_s(msg: AbstractMessage):
        serialized = { x: getattr(msg, x)
                       for x in dir(msg)
                       if not x.startswith("_")
                       and not callable(getattr(msg, x)) }

        return json.dumps(serialized, default=serialize_json, indent=4)


def debug_dump_message(msg: AbstractMessage, name: str):
        logger.debug("Debug dump for message: {}".format(name))
        for line in pprint_message_s(msg).splitlines():
                logger.debug(line)
        logger.debug("Encoded msg object:")
        logger.debug(binascii.hexlify(msg.encode()))
