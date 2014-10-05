import socket

import click

from construct import UBInt16

from tlsenum.parse_hello import (
    ClientHello, Extensions, HandshakeFailure, ServerHello
)
from tlsenum.mappings import CipherSuites, ECCurves, ECPointFormat

CONTEXT_SETTINGS = dict(help_option_names=["-h", "--help"])


def send_client_hello(host, port, data):
    """
    Sends a ClientHello message in bytes.

    Returns a ServerHello message in bytes

    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    s.send(data)

    server_hello = s.recv(5)
    server_hello += s.recv(UBInt16("length").parse(server_hello[3:5]))

    return server_hello


@click.command(context_settings=CONTEXT_SETTINGS)
@click.argument("host", type=click.STRING)
@click.argument("port", type=click.INT)
@click.option("--verify-cert", is_flag=True)
def cli(host, port, verify_cert):
    """
    A command line tool to enumerate TLS cipher-suites supported by a server.

    """
    cipher_suites_list = [i.name for i in CipherSuites]

    extension = Extensions()
    extension.sni = host
    extension.ec_curves = [i.name for i in ECCurves]
    extension.ec_point_format = [i.name for i in ECPointFormat]

    client_hello = ClientHello()
    client_hello.protocol_version = "1.2"
    client_hello.deflate = False
    client_hello.extensions = extension.build()

    supported_cipher_suites = []

    while True:
        client_hello.cipher_suites = cipher_suites_list
        server_hello = send_client_hello(host, port, client_hello.build())
        try:
            server_hello = ServerHello.parse_server_hello(server_hello)
        except HandshakeFailure:
            break

        supported_cipher_suites.append(server_hello.cipher_suite)
        cipher_suites_list.remove(server_hello.cipher_suite)

    for i in supported_cipher_suites:
        print(i)
