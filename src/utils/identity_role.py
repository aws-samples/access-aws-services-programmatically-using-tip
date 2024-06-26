import json
from datetime import datetime, timezone

from ..utils.app_config import AppConfig, ConfigUtils


class IdentityRole:
    def __init__(
        self,
        access_key_id: str = None,
        secret_access_key: str = None,
        session_token: str = None,
        expiration: str = None,
    ):
        """
        Initializes the IdentityRole instance with credentials.

        Args:
            access_key_id (Optional[str]): AWS Access Key ID.
            secret_access_key (Optional[str]): AWS Secret Access Key.
            session_token (Optional[str]): AWS Session Token.
            expiration (Optional[str]): Expiration time as an ISO 8601 formatted string.
        """
        self.access_key_id = access_key_id
        self.secret_access_key = secret_access_key
        self.session_token = session_token
        self.expiration = expiration

    def is_expired(self) -> bool:
        """Check if credentials are expired based on the current UTC time."""
        if not self.expiration:
            return True
        expiration_time = datetime.fromisoformat(self.expiration.replace("Z", "+00:00"))
        return expiration_time <= datetime.now(timezone.utc)

    def save(self, config_manager: AppConfig):
        """Save the current credentials to a JSON file using the provided AppConfig instance."""
        data_to_save = {
            "access_key_id": self.access_key_id,
            "secret_access_key": self.secret_access_key,
            "session_token": self.session_token,
            "expiration": self.expiration,
        }
        ConfigUtils.save_config_file(
            data_to_save, config_manager.get_file_path("identity_role_creds")
        )

    def load(self, config_manager: AppConfig):
        """Load credentials from a JSON file using the provided AppConfig instance."""
        loaded_data = ConfigUtils.load_config_file(
            config_manager.get_file_path("identity_role_creds")
        )
        if loaded_data:
            self.access_key_id = loaded_data.get("access_key_id", self.access_key_id)
            self.secret_access_key = loaded_data.get(
                "secret_access_key", self.secret_access_key
            )
            self.session_token = loaded_data.get("session_token", self.session_token)
            self.expiration = loaded_data.get("expiration", self.expiration)

    @classmethod
    def from_config_manager(cls, config_manager: AppConfig):
        """Factory method to create an IdentityRole instance from stored credentials using the provided AppConfig."""
        instance = cls()
        instance.load(config_manager)
        return instance

    def __str__(self):
        """Return a JSON string representation of the credentials."""
        credentials = {
            "Version": 1,
            "AccessKeyId": self.access_key_id,
            "SecretAccessKey": self.secret_access_key,
            "SessionToken": self.session_token,
            "Expiration": self.expiration,
        }
        return json.dumps(credentials, indent=4)
