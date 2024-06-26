import fnmatch
import hashlib
import time
from datetime import datetime, timezone

from ..utils.app_config import ConfigUtils


class StoreObject:
    def __init__(self, permission, target_type, privilege, creds):
        self.id = hash_dict(
            {
                "Permission": permission,
                "TargetType": target_type,
                "Privilege": privilege,
            }
        )
        self.permission = permission
        self.target_type = target_type
        self.privilege = privilege
        self.expiration = self.convert_to_timestamp(creds.get("Expiration"))
        self.creds = {
            key: creds.get(key)
            for key in ["AccessKeyId", "SecretAccessKey", "SessionToken"]
        }

    @staticmethod
    def convert_to_timestamp(dt):
        return dt.timestamp() if isinstance(dt, datetime) else dt

    def is_expired(self):
        """Determine if the credential is expired based on current time."""
        return self.expiration < time.time()

    def __repr__(self):
        expiration_status = "Expired" if self.is_expired() else "Valid"
        credential_info = (
            f"Permission: {self.permission}, "
            f"Target Type: {self.target_type}, Privilege: {self.privilege}, "
            f"Expiration: {self.expiration} ({expiration_status})"
        )
        return credential_info

    def get_credentials(self):
        creds = self.creds.copy()
        creds["Expiration"] = datetime.fromtimestamp(self.expiration, tz=timezone.utc)
        return creds

    def to_json(self):
        return {
            "id": self.id,
            "permission": self.permission,
            "target_type": self.target_type,
            "privilege": self.privilege,
            "expiration": self.expiration,
            "creds": self.creds,
        }


class S3AgCredsStore:
    def __init__(self):
        self.store = {}

    def __repr__(self):
        return f"S3AgCredsStore({self.store})"

    def add(self, key, permission, target_type, privilege, creds):
        """Adds a new object to the list of a specified key."""
        self.store.setdefault(key, []).append(
            StoreObject(permission, target_type, privilege, creds)
        )

    def remove(self, key, id):
        """Removes an object with the specified id from the list of a specified key."""
        if key in self.store:
            self.store[key] = [obj for obj in self.store[key] if obj.id != id]

    def list(self):
        """Lists credentials by key."""
        return [
            f"Key: {key}, {obj}"
            for key, objects in self.store.items()
            for obj in objects
        ]

    def get(self, s3_path):
        """Returns the list of objects for a specified s3_path."""
        return self.store.get(s3_path, [])

    def find_by_id(self, s3_path, id):
        """Finds an object by id within a specified s3_path."""
        for obj in self.store[s3_path]:
            if obj.id == id:
                return obj
        return None

    def find_by_access_type(self, s3_path, permission, target_type, privilege):
        """Finds an object by access type within a specified s3_path."""
        self.id = hash_dict(
            {
                "Permission": permission,
                "TargetType": target_type,
                "Privilege": privilege,
            }
        )
        for obj in self.store[s3_path]:
            if obj.id == self.id:
                return obj
        return None

    def find_key_by_pattern(self, pattern):
        """Finds items by pattern. At most one key should match."""
        for s3_path in self.store.keys():
            if fnmatch.fnmatch(s3_path, pattern) or fnmatch.fnmatch(pattern, s3_path):
                return s3_path
        return None

    @staticmethod
    def normalize_path(path):
        """
        Normalize an S3 path by ensuring it does not end with a slash unless it's a wildcard pattern.
        """
        if "*" in path or "?" in path:
            return path  # Return wildcard patterns unchanged
        return path.rstrip("/")

    def fetch_credentials(self, s3_path, permission, target_type, privilege):
        """Retrieve and validate credentials if they exist."""
        matching_key = self.find_key_by_pattern(s3_path)
        if matching_key:
            obj = self.find_by_access_type(
                matching_key, permission, target_type, privilege
            )
            if obj and not obj.is_expired():
                return obj.get_credentials()
        return None

    def prune_expired_creds(self):
        """Removes all StoreObject instances from the store that have expired creds."""
        current_time = datetime.now(timezone.utc).timestamp()
        for s3_path in list(self.store.keys()):
            matching_requests = [
                obj for obj in self.store[s3_path] if obj.expiration > current_time
            ]
            if len(matching_requests):
                self.store[s3_path] = matching_requests
            else:
                del self.store[s3_path]

    def save(self, filename: str):
        """Saves credentials to a file."""
        serializable_store = {
            k: [obj.to_json() for obj in v] for k, v in self.store.items()
        }
        ConfigUtils.save_config_file(serializable_store, filename)

    @classmethod
    def from_file(cls, filename: str):
        """Loads credentials from a file."""
        try:
            loaded_data = ConfigUtils.load_config_file(filename)
        except FileNotFoundError:
            return

        instance = cls()
        for key, objects in loaded_data.items():
            for obj in objects:
                obj["creds"]["Expiration"] = datetime.fromtimestamp(obj["expiration"])
                instance.add(
                    key,
                    obj["permission"],
                    obj["target_type"],
                    obj["privilege"],
                    obj["creds"],
                )
        instance.prune_expired_creds()
        return instance


def hash_dict(d):
    """Generates a hash for a given dictionary."""
    dict_as_tuple = tuple(sorted(d.items()))
    dict_str = str(dict_as_tuple)
    return hashlib.sha256(dict_str.encode()).hexdigest()
