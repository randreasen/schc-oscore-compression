<!-- markdown-toc start - Don't edit this section. Run M-x markdown-toc-refresh-toc -->
**Table of Contents**

- [OSCORE-SCHC Compression](#oscore-schc-compression)
    - [Getting Started](#getting-started)
        - [Requirements](#requirements)
        - [Installation](#installation)
    - [Quickstart](#quickstart)
    - [Usage](#usage)
        - [SCHC Rule generation](#schc-rule-generation)
        - [Example GET request](#example-get-request)
        - [Example CONTENT response](#example-content-response)
        - [OSCORE Context](#oscore-context)

<!-- markdown-toc end -->
# OSCORE-SCHC Compression

This repository leverages [aiocoap](https://github.com/chrysn/aiocoap) and [IMT Atlantique's Python implementation of SCHC](https://github.com/ltn22/SCHC) to implement SCHC-OSCORE compression/decompression as per [RFC 8824](https://www.rfc-editor.org/rfc/rfc8824.html).

## Getting Started

### Requirements

- Docker
- docker-compose

### Installation

Clone the repo:
```shell
git clone https://github.com/randreasen/schc-oscore-compression.git
```

Build the Docker image:
```shell
./demo.sh build
```

## Quickstart

Run the examples:
```shell
./demo.sh regenerate            # Generate the SCHC rules
./demo.sh run get-temperature   # Run pipeline for get-temperature request
./demo.sh run give-temperature  # Run pipeline for give-temperature response
```

Run the tests:
```shell
./demo.sh test
```

## Usage

The main entrypoint to the demo application is the `demo.sh` script, which has a number of sub-commands to access the demo functionality:

```shell
./demo.sh --help
Usage: ./demo.sh [OPTIONS] COMMAND [ARG...]

Options:

-h, --help Display this help.

COMMAND may be one of:

build      Build the Docker image for the demo.
regenerate Regenerate the set of SCHC rules.
test       Run the test suite.
run        Run a demo command.
context    View and manipulate filesystem context
```

### SCHC Rule generation

The SCHC Rules must be generated from `makeRule.py` before attempting to run the examples for the first time:
```shell
./demo.sh regenerate
```

This command should be re-run whenever the SCHC rules are edited for them to take effect.

### Example GET request

```shell
$ ./demo.sh run get-temperature
./demo.sh get-temperature
Running get-temperature demo
./demo.sh python ./run_demo.py --mtype CON --code GET --uri coap://127.0.0.1/temperature --mid 1 --token 0x82 --verbose --with-dump --oscore-dir oscore_dir
Original msg:     b'A\x01\x00\x01\x82\xbbtemperature'
Protected msg:    b'A\x02\x00\x01\x82\xd7\x08\tclient\xff\x00Z\xc9Q\x15\x0b\x8aN?\xd0'
Compressed msg:   b'\x00\x14\x00\xb5\x92\xa2*\x17\x14\x9c\x7f\xa0'
Decompressed msg: b'A\x02\x00\x01\x82\xd7\x08\tclient\xff\x00Z\xc9Q\x15\x0b\x8aN?\xd0'
Decrypted msg:    b'A\x01\x00\x01\x82\xbbtemperature'
-----------------------------------------------------
Original msg:     4101000182bb74656d7065726174757265
Protected msg:    4102000182d70809636c69656e74ff005ac951150b8a4e3fd0
Compressed msg:   001400b592a22a17149c7fa0
Decompressed msg: 4102000182d70809636c69656e74ff005ac951150b8a4e3fd0
Decrypted msg:    4101000182bb74656d7065726174757265
Successful decryption
Original msg length:   17
Protected msg length:  25
Compressed msg length: 12
End-to-end msg length factor: 70.59%
```

### Example CONTENT response

NOTE: To retrieve the credentials for the response, OSCORE reuses some of the information from the request that originated it. To successfully get the credentials for the POST response, it should be run following the GET `/temperature` request.

```shell
$ ./demo.sh run give-temperature
./demo.sh give-temperature
Running give-temperature demo
./demo.sh python ./run_demo.py --mtype ACK --code CONTENT --mid 2 --token 0x82 --verbose --with-dump --role server --oscore-dir oscore_dir --payload 32332043
Original msg:     b'aE\x00\x02\x82\xff23 C'
Protected msg:    b'aD\x00\x02\x82\xd0\x08\xff\xfaoN\\\nd\xb5v\xcd\x8e\xcc\r\x1d,'
Compressed msg:   b'\x00%\xf4\xde\x9c\xb8\x14\xc9j\xed\x9b\x1d\x98\x1a:X'
Decompressed msg: b'aD\x00\x02\x82\xd0\x08\xff\xfaoN\\\nd\xb5v\xcd\x8e\xcc\r\x1d,'
Decrypted msg:    b'aE\x00\x02\x82\xff23 C'
-----------------------------------------------------
Original msg:     6145000282ff32332043
Protected msg:    6144000282d008fffa6f4e5c0a64b576cd8ecc0d1d2c
Compressed msg:   0025f4de9cb814c96aed9b1d981a3a58
Decompressed msg: 6144000282d008fffa6f4e5c0a64b576cd8ecc0d1d2c
Decrypted msg:    6145000282ff32332043
Successful decryption
Original msg length:   10
Protected msg length:  22
Compressed msg length: 16
End-to-end msg length factor: 160.00%
```

### OSCORE Context

The credentials and stored context at any point can be visualized:
```shell
./demo.sh context show
```

And reset:
```shell
./demo.sh context clear
```
