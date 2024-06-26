import time

import jwt

from ..utils.app_config import AppConfig, ConfigUtils

SUPPORTED_IDPS = {
    "okta": "src.auth.okta_auth.OktaAuth",
    "entra-id": "src.auth.entra_auth.EntraAuth",
    "cognito": "src.auth.cognito_auth.CognitoAuth",
    # Add other IdPs here, e.g., 'google': 'auth_google.AuthGoogle',
}


class BaseAuth:
    """
    Base authentication class providing basic functionalities for handling
    authentication configurations and token operations.
    """

    def __init__(self, config_manager: AppConfig):
        """
        Initializes the BaseAuth class with an external configuration manager.

        Args:
            config_manager (AppConfig): The configuration manager instance that handles file operations.
        """
        self.token = {}
        self.config_manager = config_manager

    def configure(self, **kwargs):
        """
        Configures authentication parameters. Prompts for token exchange URL if not provided.

        Args:
            **kwargs: Arbitrary keyword arguments, expected to contain 'token_exchange_url'.
        """
        token_exchange_application_arn = kwargs.get("token_exchange_application_arn")
        if token_exchange_application_arn is None or kwargs.get("force_prompt_config"):
            token_exchange_application_arn = input(
                "Enter AWS Identity Center customer managed application ARN: "
            )
        self.config_manager.config["token_exchange_application_arn"] = (
            token_exchange_application_arn
        )

        oidc_role_arn = kwargs.get("oidc_role_arn")
        if oidc_role_arn is None or kwargs.get("force_prompt_config"):
            oidc_role_arn = input(
                "Enter the IAM Role ARN for the initial Identity Center token exchange with your trusted IdP: "
            )
        self.config_manager.config["oidc_role_arn"] = oidc_role_arn

        id_enhanced_role_arn = kwargs.get("id_enhanced_role_arn")
        if id_enhanced_role_arn is None or kwargs.get("force_prompt_config"):
            id_enhanced_role_arn = input(
                "Enter the IAM Role ARN to be used to create the identity-enhanced IAM role session: "
            )
        self.config_manager.config["id_enhanced_role_arn"] = id_enhanced_role_arn

    def save_idp_token(self):
        """
        Saves the authentication token to a file using the provided token file path.

        Args:
            token_file (str): Path to the file where the token should be saved.
        """
        token_data = {
            "token": self.token.get("token", ""),
            "refresh_token": self.token.get("refresh_token", ""),
            "requires_refresh": self.token.get("requires_refresh", True),
        }

        ConfigUtils.save_config_file(
            config_data=token_data,
            file_path=self.config_manager.get_file_path("idp_token"),
        )

    def load_idp_token(self):
        """
        Loads the authentication token from a specified file.

        Args:
            token_file (str): Path to the file from which to load the token.

        Returns:
            bool: True if the token is successfully loaded, False otherwise.

        Raises:
            FileNotFoundError: If the token file does not exist.
            ValueError: If essential token components are missing.
        """
        try:
            auth_token_idp = ConfigUtils.load_config_file(
                self.config_manager.get_file_path("idp_token")
            )
        except FileNotFoundError:
            raise FileNotFoundError("Token file does not exist.")
        except ValueError as e:
            raise ValueError(f"Error loading token: {e}")

        if not auth_token_idp.get("token"):
            raise ValueError("Missing token from cached file.")

        self.token.update(
            {
                "token": auth_token_idp.get("token"),
                "refresh_token": auth_token_idp.get("refresh_token", ""),
                "requires_refresh": auth_token_idp.get("requires_refresh", True),
            }
        )

        return True

    def load_token(self):
        """
        Loads the authentication token from a specified file.

        Args:
            token_file (str): Path to the file from which to load the token.

        Returns:
            bool: True if the token is successfully loaded, False otherwise.

        Raises:
            FileNotFoundError: If the token file does not exist.
            ValueError: If essential token components are missing.
        """
        try:
            auth_response = self.config_manager.load_token_file()
        except FileNotFoundError:
            raise FileNotFoundError("Token file does not exist.")
        except ValueError as e:
            raise ValueError(f"Error loading token: {e}")

        if not auth_response.get("token"):
            raise ValueError("Missing token from cached file.")

        self.token.update(
            {
                "token": auth_response.get("token"),
                "refresh_token": auth_response.get("refresh_token", ""),
                "requires_refresh": auth_response.get("requires_refresh", True),
            }
        )

        return True

    def force_require_refresh(self):
        """Updates the status to force refresh (useful when the token already exchanged with IdC)"""
        self.token["requires_refresh"] = True
        self.save_idp_token()

    def should_refresh_token(self):
        if self.token["requires_refresh"]:
            return True

        current_time = int(time.time())
        token = jwt.decode(self.token["token"], options={"verify_signature": False})

        if token.get("exp") > current_time:
            return False

        return hasattr(self.token, "refresh_token")

    def check_if_authenticated(self):
        raise NotImplementedError(
            "The configure method must be implemented by subclasses."
        )

    def authenticate(self):
        raise NotImplementedError(
            "The authenticate method must be implemented by subclasses."
        )

    def refresh_token(self):
        raise NotImplementedError(
            "The authenticate method must be implemented by subclasses."
        )
