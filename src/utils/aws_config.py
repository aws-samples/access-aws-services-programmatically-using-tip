import configparser
import os


def add_aws_profile(profile_name, command):
    aws_config_path = os.path.expanduser("~/.aws/config")
    config = configparser.ConfigParser()

    if os.path.exists(aws_config_path):
        config.read(aws_config_path)

    profile_section = f"profile {profile_name}"
    if profile_section not in config.sections():
        config.add_section(profile_section)

    config.set(profile_section, "credential_process", command)

    with open(aws_config_path, "w", encoding="utf-8") as configfile:
        config.write(configfile)
