tlsenum
=======

[![Build Status](https://travis-ci.org/Ayrx/tlsenum.svg?branch=add-travis)](htt
ps://travis-ci.org/Ayrx/tlsenum)
[![Coverage Status](https://coveralls.io/repos/Ayrx/tlsenum/badge.png?branch=ma
ster)](https://coveralls.io/r/Ayrx/tlsenum?branch=master)

tlsenum is a command-line TLS enumeration tool that attempts to enumerate what
TLS cipher suites a server supports and list them in order of priority.

It works by sending out sending out TLS `ClientHello` messages and parsing the
`ServerHello` responses from the server.

tlsenum assumes that the server decides the preferred cipher suite, ignoring
the preference indicated by the client. While this is not strictly guaranteed
by the TLS specification, it seems like a fairly common implementation detail.

Requirements
------------

The basic functionality of tlsenum simply require Python 3. It has been written
and tested with Python 3.3.

Some optional features may require additional modules to be installed. The
specific modules required will be listed when using the features if they are
not already installed.

A complete list of dependencies can be found in `requirements.txt`. Simply
install the dependencies using `pip` to access all the features of tlsenum.

```
pip install -r requirements.txt
```

Usage
-----

Using this tool is fairly simple, here is an  example of the tool's results
when scanning twitter.com.

```
[ayrx@division tlsenum]$ ./tlsenum.py twitter.com 443
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

License
-------
```
The MIT License (MIT)

Copyright (c) 2014 Terry Chia

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
of the Software, and to permit persons to whom the Software is furnished to do
so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
