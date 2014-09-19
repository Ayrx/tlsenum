import click


CONTEXT_SETTINGS = dict(help_option_names=["-h", "--help"])


@click.command(context_settings=CONTEXT_SETTINGS)
@click.argument("host", type=click.STRING)
@click.argument("port", type=click.INT)
@click.option("--verify-cert", is_flag=True)
def cli(host, port, verify_cert):
    """
    A command line tool to enumerate TLS cipher-suites supported by a server.

    """
    pass
