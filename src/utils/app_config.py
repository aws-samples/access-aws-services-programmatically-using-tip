import json
import logging
import os

logger = logging.getLogger(__name__)


class AppConfig:
    """
    Manages application configuration including file paths and loading/saving configurations.

    Attributes:
        home (str): The directory where configuration files are stored.
        files (dict): Dictionary of file paths for various configuration files.
    """

    def __init__(self, home=None):
        """
        Initializes the application configuration paths.

        Args:
            home (str, optional): Base directory for storing configuration files.
                Defaults to '~/.aws_tip_cli' or the value set by the AWS_TIP_CLI environment variable.
        """
        self.home = self._initialize_home_directory(home)
        self.files = {
            "config": os.path.join(self.home, "config.json"),
            "idp_token": os.path.join(self.home, "idp_token.json"),
            "identity_role_creds": os.path.join(self.home, "role_creds.json"),
            "s3ag_creds": os.path.join(self.home, "s3_creds.json"),
        }

        self.config = self.load()

    def _initialize_home_directory(self, home):
        """Sets up the configuration directory, creating it if it does not exist."""
        default_home = os.getenv("AWS_TIP_CLI", os.path.expanduser("~/.aws_tip_cli"))
        home_path = os.path.abspath(home or default_home)
        os.makedirs(home_path, exist_ok=True)
        return home_path

    def get_file_path(self, key):
        """Returns the file path associated with the given key."""
        return self.files.get(key)

    def save(self):
        """Saves the main application configuration to the file."""
        ConfigUtils.save_config_file(self.config, self.get_file_path("config"))

    def load(self):
        """Loads the main application configuration from the file."""
        return ConfigUtils.load_config_file(self.get_file_path("config"))


class ConfigUtils:
    """Provides utility functions for handling configuration file operations."""

    @staticmethod
    def load_config_file(file_path):
        """Attempts to load a JSON configuration file from the specified path."""
        try:
            with open(file_path, "r", encoding="utf-8") as file:
                return json.load(file)
        except FileNotFoundError:
            return {}
        except json.JSONDecodeError:
            logger.error(f"Error decoding JSON from {file_path}.")
            return {}

    @staticmethod
    def save_config_file(config_data, file_path):
        """Attempts to save configuration data to a JSON file at the specified path."""
        try:
            with open(file_path, "w", encoding="utf-8") as file:
                json.dump(config_data, file, indent=4)
        except IOError as e:
            logger.error(f"Failed to save configuration to {file_path}: {e}")
