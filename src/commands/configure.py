import json
import logging
import os

import click

from ..auth.base_auth import SUPPORTED_IDPS
from ..utils.app_config import AppConfig
from ..utils.auth_loader import load_auth_class
from ..utils.cfn_generator import \
    generate_cfn_template as _generate_cfn_template

logger = logging.getLogger(__name__)


@click.group()
@click.pass_context
def configure(ctx: AppConfig):
    """Configure the application"""

    ctx.ensure_object(dict)
    app_config = ctx.obj.setdefault("app_config", AppConfig())


@configure.command()
@click.argument("oidc_url")
@click.argument("oidc_aud")
@click.argument("certificate_fingerprint", required=False)
@click.pass_context
def generate_cfn_template(ctx, oidc_url, oidc_aud, certificate_fingerprint):
    """Configure the AWS Account IAM roles for a specific Identity Provider."""
    t = _generate_cfn_template(oidc_url, oidc_aud, certificate_fingerprint)
    click.echo(t)


@configure.command()
@click.option(
    "--provider",
    type=click.Choice(SUPPORTED_IDPS.keys()),
    prompt=True,
    help="Select an Identity Provider.",
)
@click.option(
    "--config",
    help="Configuration in JSON format or path to a JSON file",
    default=None,
)
@click.pass_context
def idp(ctx, provider: str, config: str):
    """Configure the application for a specific Identity Provider."""
    app_config = ctx.obj["app_config"]

    # Load the configuration, if the parameter was set
    # Determine if the config parameter is a file path or a JSON string
    force_prompt_config = False
    config_data = {}
    if config and os.path.exists(config) and config.endswith(".json"):
        config_data = load_config_from_file(config)
    elif not config:
        config_data = app_config.load()
        force_prompt_config = True
    else:
        config_data = parse_json_string(config)

    # Load and configure the authentication class
    auth_instance = load_auth_class(app_config, provider)
    if auth_instance:
        auth_instance.configure(force_prompt_config=force_prompt_config, **config_data)
        click.echo("Configuration saved.")
    else:
        logger.error("Selected IdP is not supported.")
        click.echo("Selected IdP is not supported.")


def load_config_from_file(config_path):
    """Load configuration data from a JSON file."""
    try:
        with open(config_path, "r", encoding="utf-8") as file:
            return json.load(file)
    except json.JSONDecodeError:
        logger.error("Failed to decode JSON from file, check your syntax.")
        click.echo("Failed to decode JSON from file, check your syntax.")
        return {}
    except FileNotFoundError:
        logger.error("JSON file not found.")
        click.echo("JSON file not found.")
        return {}


def parse_json_string(json_string):
    """Parse configuration data from a JSON string."""
    try:
        return json.loads(json_string)
    except json.JSONDecodeError:
        logger.error("Failed to decode JSON from string, check your syntax.")
        click.echo("Failed to decode JSON from string, check your syntax.")
        return {}
