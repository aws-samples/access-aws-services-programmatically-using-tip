import base64
import json
import logging
import os
from importlib import import_module

import boto3
import botocore

from ..auth.base_auth import SUPPORTED_IDPS, BaseAuth
from .identity_role import IdentityRole

logger = logging.getLogger(__name__)


def load_auth_class(app_config, idp):
    """
    Loads and returns an authentication class based on the identity provider.

    Args:
        idp (str): Identifier for the identity provider.

    Returns:
        BaseAuth: An instance of the authentication class.

    Raises:
        ImportError: If the class cannot be loaded or is not a subclass of BaseAuth.
    """
    try:
        module_name, class_name = SUPPORTED_IDPS[idp].rsplit(".", 1)
        AuthClass = getattr(import_module(module_name), class_name)
        if issubclass(AuthClass, BaseAuth):
            return AuthClass(app_config)
        else:
            logger.error(f"{class_name} is not a subclass of BaseAuth")
            raise TypeError(f"{class_name} is not a valid authentication class")

    except (ImportError, AttributeError) as e:
        logger.exception("Failed to load authentication class: %s", str(e))
        raise ImportError("Authentication class could not be loaded") from e

    except KeyError:
        logger.exception(f"No configuration for IdP: {idp}")
        raise KeyError(f"No configuration for IdP: {idp}")


def handle_token_refresh(auth_instance):
    """
    Load the token, check if it needs refresh, and perform refresh if necessary.
    """
    if auth_instance.should_refresh_token():
        logger.info("IdP token expired - trying to refresh it.")
        if not auth_instance.refresh_token():
            raise TokenRefreshError("Failed to refresh token.")


def perform_identity_exchange_and_save(auth_instance, app_config):
    """
    Perform the identity token exchange and create an identity-enhanced IAM Role session.
    """

    id_enhanced_creds = do_exchange(
        auth_instance.token["token"],
        app_config.config["token_exchange_application_arn"],
        app_config.config["oidc_role_arn"],
        app_config.config["id_enhanced_role_arn"],
    )

    if id_enhanced_creds:
        id_enhanced_creds.save(app_config)
        auth_instance.force_require_refresh()
        return id_enhanced_creds
    else:
        raise IdentityEnhancedSessionCreationError(
            "Failed to create identity-enhanced session."
        )


def do_exchange(token, token_exchange_app_arn, intermediary_role_arn, tip_role_arn):
    """
    Exchange an ID token for user credentials using the specified API endpoint.

    Args:
        token (str): The token to exchange.
        token_exchange_app_arn (str): The ARN of the token echange application
        intermediary_role_arn (str): The ARN of the role that can be assumed using the JWT token
        tip_role_arn (str): The ARN of the role to use to create the identity-enhanced IAM role session

    Returns:
        IdentityRole: An initialized IdentityRole object with the exchanged credentials.
    """
    captured_vars = _capture_and_clear_aws_env_vars()
    # Create an STS client using the anonymous session
    sts = boto3.client("sts")

    try:
        # Assume the first role using the JWT token
        first_role_response = sts.assume_role_with_web_identity(
            RoleArn=intermediary_role_arn,
            RoleSessionName="AssumeFirstRole",
            WebIdentityToken=token,
            DurationSeconds=900,
        )
        credentials = first_role_response["Credentials"]

        session = boto3.Session(
            aws_access_key_id=credentials["AccessKeyId"],
            aws_secret_access_key=credentials["SecretAccessKey"],
            aws_session_token=credentials["SessionToken"],
        )
        # Use the session to exchange the token
        sso_oidc = session.client("sso-oidc")

        sso_oidc_response = sso_oidc.create_token_with_iam(
            clientId=token_exchange_app_arn,
            grantType="urn:ietf:params:oauth:grant-type:jwt-bearer",
            assertion=token,
        )

        # Create a identity enhanced session
        tip_token_id_token_decoded = _decode_jwt(sso_oidc_response["idToken"])
        sts_identity_context = tip_token_id_token_decoded["sts:identity_context"]
        idc_user_id = tip_token_id_token_decoded["sub"]

        id_enhanced_role_response = session.client("sts").assume_role(
            RoleArn=tip_role_arn,
            RoleSessionName=f"tip-{idc_user_id}",
            ProvidedContexts=[
                {
                    "ProviderArn": "arn:aws:iam::aws:contextProvider/IdentityCenter",
                    "ContextAssertion": sts_identity_context,
                },
            ],
        )
        id_enhanced_role_creds = id_enhanced_role_response["Credentials"]

        return IdentityRole(
            access_key_id=id_enhanced_role_creds["AccessKeyId"],
            secret_access_key=id_enhanced_role_creds["SecretAccessKey"],
            session_token=id_enhanced_role_creds["SessionToken"],
            expiration=id_enhanced_role_creds["Expiration"].isoformat(),
        )

    except botocore.exceptions.ClientError as e:
        logger.error(f"Error when exchanging credentials: {e}")
        return None
    finally:
        # Restore the environment variables
        _restore_aws_env_vars(captured_vars)


def _decode_jwt(token):
    """
    Decodes the payload of a JWT without verifying its signature.

    :param token: str - The JWT token to be decoded
    :return: dict - The decoded payload of the token
    """
    # Split the token into its parts: Header, Payload, Signature
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("Invalid JWT token")

    # Base64 decode the payload part
    payload = parts[1]
    padding = "=" * (4 - len(payload) % 4)
    decoded_bytes = base64.urlsafe_b64decode(payload + padding)
    decoded_payload = json.loads(decoded_bytes.decode("utf-8"))

    return decoded_payload


def _capture_and_clear_aws_env_vars():
    # List of environment variables to capture and clear
    aws_env_vars = [
        "AWS_PROFILE",
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
    ]
    # Capture current environment variables
    captured_vars = {var: os.environ.get(var) for var in aws_env_vars}
    # Clear the environment variables
    for var in aws_env_vars:
        if var in os.environ:
            del os.environ[var]
    return captured_vars


def _restore_aws_env_vars(captured_vars):
    # Restore the environment variables
    for var, value in captured_vars.items():
        if value is not None:
            os.environ[var] = value


class TokenRefreshError(Exception):
    pass


class IdentityEnhancedSessionCreationError(Exception):
    """Raised when there is an error creating an identity-enhanced session."""

    pass
