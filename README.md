tlsenum
=======

[![Build Status](https://travis-ci.org/Ayrx/tlsenum.svg?branch=master)](https://travis-ci.org/Ayrx/tlsenum)
[![Coverage Status](https://coveralls.io/repos/Ayrx/tlsenum/badge.png?branch=master)](https://coveralls.io/r/Ayrx/tlsenum?branch=master)

tlsenum is a command-line TLS enumeration tool that attempts to enumerate what
TLS cipher suites a server supports and list them in order of priority.

It works by sending out sending out TLS `ClientHello` messages and parsing the
`ServerHello` responses from the server.

tlsenum assumes that the server decides the preferred cipher suite, ignoring
the preference indicated by the client. While this is not strictly guaranteed
by the TLS specification, it seems like a fairly common implementation detail.

Installation
------------

`tlsenum` requires Python 3 and can be installed with pip.

    $ pip install tlsenum

Usage
-----

Using this tool is fairly simple, here is an  example of the tool's results
when scanning twitter.com.

```
[ayrx@division tlsenum]$ tlsenum twitter.com 443
TLS Versions supported by server: 3.0, 1.0, 1.1, 1.2
Deflate compression: no
Supported Cipher suites in order of priority:
TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
TLS_ECDHE_RSA_WITH_RC4_128_SHA
TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
TLS_RSA_WITH_AES_128_GCM_SHA256
TLS_RSA_WITH_RC4_128_SHA
TLS_RSA_WITH_RC4_128_MD5
TLS_RSA_WITH_AES_128_CBC_SHA
TLS_RSA_WITH_AES_256_CBC_SHA
TLS_RSA_WITH_3DES_EDE_CBC_SHA
```

Do look at `tlsenum -h` for other options.
