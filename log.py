import logging

import os
import io
from pprint import pprint

LOGLEVEL = os.getenv("LOGLEVEL") or "INFO"
LOG_FORMAT="%(asctime)s [%(filename)s:%(lineno)d]-%(levelname)s-: %(message)s"

logging.basicConfig(format=LOG_FORMAT)

def basicConfig(format=LOG_FORMAT):
    logging.basicConfig(format=LOG_FORMAT)

def getLogger(name):
    logger = logging.getLogger(name)
    setLevel(logger, LOGLEVEL)
    return logger

def setLevel(logger, levelname):
    logger.setLevel(getattr(logging, levelname.upper()))


def pprint_s(*args) -> str:
    stream = io.StringIO()
    pprint(*args, stream=stream)
    return stream.getvalue()
