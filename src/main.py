import logging
import os

import click

from .commands.auth import auth
from .commands.configure import configure
from .commands.diag import diag
from .commands.s3ag import s3ag
from .utils.app_config import AppConfig

logging.basicConfig(level=os.environ.get("LOGLEVEL", "INFO").upper())


@click.group()
@click.pass_context
def cli(ctx):
    """A CLI application to access AWS services using trusted identity propagation."""
    ctx.ensure_object(dict)
    ctx.obj["app_config"] = AppConfig()
    pass


cli.add_command(configure)
cli.add_command(auth)
cli.add_command(s3ag)
cli.add_command(diag)


if __name__ == "__main__":
    cli()
