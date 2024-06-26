import logging

import click

from ..auth.base_auth import BaseAuth
from ..config import COMMAND_NAME
from ..utils.app_config import AppConfig
from ..utils.auth_loader import (handle_token_refresh, load_auth_class,
                                 perform_identity_exchange_and_save)
from ..utils.aws_config import add_aws_profile
from ..utils.identity_role import IdentityRole

logger = logging.getLogger(__name__)


@click.group(invoke_without_command=True)
@click.option("--help", is_flag=True, default=False, help="Show this message and exit.")
@click.pass_context
def auth(ctx, help):
    """Retrieves OAuth2.0 token with the configured IdP."""
    ctx.ensure_object(dict)
    if "app_config" not in ctx.obj:
        ctx.obj["app_config"] = AppConfig()

    # Load the authentication instance once based on the config and store in context
    app_config = ctx.obj["app_config"]
    if "idp" in app_config.config:
        ctx.obj["auth_instance"] = load_auth_class(app_config, app_config.config["idp"])
    else:
        raise click.ClickException("Identity Provider (IdP) not configured.")

    if ctx.invoked_subcommand is None:
        if help:
            click.echo(ctx.get_help())
            ctx.exit()
        if ctx.obj["auth_instance"].authenticate():
            click.echo("Authentication successful.")
        else:
            click.echo("Authentication failed.")


@auth.command()
@click.pass_context
def refresh_token(ctx):
    """Refresh the OAuth2.0 token with the configured IdP."""
    auth_instance = ctx.obj["auth_instance"]
    auth_instance.load_idp_token()

    refresh_worked = auth_instance.refresh_token()
    if refresh_worked:
        click.echo(f"Refresh ok - token expires at {refresh_worked}.")
    else:
        click.echo("Could not refresh the token - please authenticate again.")


@auth.command()
@click.pass_context
def get_iam_credentials(ctx):
    """Retrieves IAM credentials of the identity enhanced session."""
    app_config = ctx.obj["app_config"]
    auth_instance = ctx.obj["auth_instance"]
    # Retrieve current IdP token
    auth_instance.load_idp_token()

    identity_role = IdentityRole.from_config_manager(app_config)
    if identity_role and not identity_role.is_expired():
        click.echo(identity_role)
    else:
        logger.info("No identity role, performing exchange")
        handle_token_refresh(auth_instance)
        id_enhanced_creds = perform_identity_exchange_and_save(
            auth_instance, app_config
        )
        click.echo(id_enhanced_creds)


@auth.command()
@click.option("--profile", required=True, help="Name of the AWS profile.")
def set_aws_profile(profile):
    """Sets AWS profile in the config file."""
    command = f"{COMMAND_NAME} auth get-iam-credentials"
    add_aws_profile(profile, command)
    click.echo(f"Profile {profile} added/updated successfully.")
