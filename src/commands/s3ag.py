import json
import logging

import boto3
import botocore
import click

from ..utils.app_config import AppConfig
from ..utils.auth_loader import (handle_token_refresh, load_auth_class,
                                 perform_identity_exchange_and_save)
from ..utils.identity_role import IdentityRole
from ..utils.s3_ag_creds import S3AgCredsStore

logger = logging.getLogger(__name__)


@click.group()
@click.pass_context
def s3ag(ctx):
    """Amazon S3 Access Grant commands"""

    ctx.ensure_object(dict)
    app_config = ctx.obj.setdefault("app_config", AppConfig())
    ctx.obj["identity_role"] = IdentityRole.from_config_manager(app_config)
    app_config = ctx.obj["app_config"]
    if "idp" not in app_config.config:
        logger.error("Missing configuration - run configure first")
        exit(1)

    ctx.obj["auth_instance"] = load_auth_class(app_config, app_config.config["idp"])

    auth_instance = ctx.obj["auth_instance"]
    # Retrieve current IdP token
    auth_instance.load_idp_token()

    identity_role = IdentityRole.from_config_manager(app_config)
    if not identity_role or identity_role.is_expired():
        logger.info("No identity role, performing exchange")
        handle_token_refresh(auth_instance)
        perform_identity_exchange_and_save(auth_instance, app_config)

    ctx.obj["creds_store"] = (
        S3AgCredsStore.from_file(ctx.obj["app_config"].get_file_path("s3ag_creds"))
        or S3AgCredsStore()
    )


@s3ag.command()
@click.option("--force-new-creds", is_flag=True, default=False)
@click.option("--account-id", required=False)
@click.option(
    "--permission", type=click.Choice(["READ", "WRITE", "READWRITE"]), default="READ"
)
@click.option("--duration-seconds", default=3600)
@click.option(
    "--target-type", type=click.Choice(["Object", "Prefix"]), default="Prefix"
)
@click.option(
    "--privilege", type=click.Choice(["Default", "Minimal"]), default="Default"
)
@click.argument("s3_path")
@click.pass_context
def get_data_access(
    ctx,
    force_new_creds,
    account_id,
    permission,
    duration_seconds,
    target_type,
    privilege,
    s3_path,
):
    """Retrieve and cache IAM credentials with S3 Access Grant to a given S3 path"""
    creds = _fetch_or_request_credentials(
        ctx,
        permission,
        duration_seconds,
        target_type,
        privilege,
        s3_path,
        account_id,
        force_new_creds,
    )
    if creds:
        formatted_creds = {
            "Version": 1,
            "AccessKeyId": creds.get("AccessKeyId"),
            "SecretAccessKey": creds.get("SecretAccessKey"),
            "SessionToken": creds.get("SessionToken"),
            "Expiration": creds.get("Expiration").astimezone().isoformat(),
        }
        click.echo(json.dumps(formatted_creds, indent=4))
    else:
        click.echo("Failed to retrieve S3 credentials.")


@s3ag.command()
@click.pass_context
def list_credentials(ctx):
    """Lists all stored S3 Access Grants credentials."""
    creds_store = ctx.obj["creds_store"]
    creds_list = creds_store.list()

    if creds_list:
        click.secho("Credentials Information:", bold=True)
        for cred in creds_list:
            click.echo(cred)
        click.echo()
    else:
        click.secho("No credentials found.", fg="red", bold=True)


@s3ag.command()
@click.pass_context
def clear_credentials(ctx):
    """Clear all stored S3 Access Grants credentials."""
    creds_store = S3AgCredsStore()
    creds_store.save(ctx.obj["app_config"].get_file_path("s3ag_creds"))


def _fetch_or_request_credentials(
    ctx,
    permission,
    duration_seconds,
    target_type,
    privilege,
    s3_path,
    account_id=None,
    force_new_creds=False,
):
    """Fetch existing credentials or request new ones if necessary."""
    creds_store = ctx.obj["creds_store"]
    if not force_new_creds:
        creds = creds_store.fetch_credentials(
            s3_path, permission, target_type, privilege
        )
        if creds:
            return creds

    return _request_new_grant(
        ctx, permission, duration_seconds, target_type, privilege, s3_path, account_id
    )


def _request_new_grant(
    ctx, permission, duration_seconds, target_type, privilege, s3_path, account_id=None
):
    creds_store = ctx.obj["creds_store"]
    identity_creds = ctx.obj["identity_role"]
    session = boto3.Session(
        aws_access_key_id=identity_creds.access_key_id,
        aws_secret_access_key=identity_creds.secret_access_key,
        aws_session_token=identity_creds.session_token,
    )

    # If no account id is provided, use the one from the identity enhanced session
    if not account_id:
        account_id = session.client("sts").get_caller_identity()["Account"]

    s3_control_client = session.client("s3control")
    params = {
        "AccountId": account_id,
        "Permission": permission,
        "Target": s3_path,
        "Privilege": privilege,
        "TargetType": None if target_type != "Object" else "Object",
        "DurationSeconds": duration_seconds,
    }
    not_none_params = {k: v for k, v in params.items() if v is not None}

    try:
        resp = s3_control_client.get_data_access(**not_none_params)
    except botocore.exceptions.ClientError as err:
        click.echo(f"Error: {err}")
        return

    matched_target = resp.get("MatchedGrantTarget")
    s3_ag_creds = resp.get("Credentials")

    creds_store.add(matched_target, permission, target_type, privilege, s3_ag_creds)
    creds_store.save(ctx.obj["app_config"].get_file_path("s3ag_creds"))

    return s3_ag_creds
