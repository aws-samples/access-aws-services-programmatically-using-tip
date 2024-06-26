import base64
import json

import click


def get_idp_token(auth_instance):
    auth_instance.load_idp_token()
    if "token" not in auth_instance.token:
        click.error(
            "The diagnostic tool requires at least one JWT from your Identity Provider. Please authenticate first"
        )
        exit(1)
    return auth_instance.token["token"]


def parse_application_arn(token_exchange_application_arn):
    """
    Parses an IAM Identity Center Application ARN and returns the instance ID, partition, and IDC ARN.

    Args:
        token_exchange_application_arn (str): The IAM Identity Center Application ARN.

    Returns:
        string: The IDC ARN constructed from the instance ID and partition.
    """
    instance_id = token_exchange_application_arn.split("/")[1]
    partition = token_exchange_application_arn.split(":")[1]
    return f"arn:{partition}:sso:::instance/{instance_id}"


def filter_token_issuer_arns_by_audience(grants_data, audience):
    """
    Filters the TrustedTokenIssuerArn values from grants with a GrantType of 'urn:ietf:params:oauth:grant-type:jwt-bearer'
    where the AuthorizedAudiences contains the specified audience.

    Args:
        grants_data (dict): A dictionary containing the grants data.
        audience (str): The audience value to filter for.

    Returns:
        list: A list of TrustedTokenIssuerArn values that match the specified audience.
    """
    token_issuer_arns = []
    jwt_bearer_grants = filter_jwt_bearer_grants(grants_data)

    for grant in jwt_bearer_grants:
        jwt_bearer = grant["Grant"]["JwtBearer"]
        authorized_token_issuers = jwt_bearer["AuthorizedTokenIssuers"]

        for issuer in authorized_token_issuers:
            if audience in issuer["AuthorizedAudiences"]:
                token_issuer_arns.append(issuer["TrustedTokenIssuerArn"])
                break  # Stop checking other issuers for this grant

    return token_issuer_arns


def print_jwt_bearer_token_issuers(grants_data):
    """
    Prints the TrustedTokenIssuerArn and its corresponding AuthorizedAudiences for each grant with a GrantType of 'urn:ietf:params:oauth:grant-type:jwt-bearer'.

    Args:
        grants_data (dict): A dictionary containing the grants data.
    """
    jwt_bearer_grants = filter_jwt_bearer_grants(grants_data)

    for grant in jwt_bearer_grants:
        print(f"GrantType: {grant['GrantType']}")

        jwt_bearer = grant["Grant"]["JwtBearer"]
        authorized_token_issuers = jwt_bearer["AuthorizedTokenIssuers"]

        for issuer in authorized_token_issuers:
            print(f"  TrustedTokenIssuerArn: {issuer['TrustedTokenIssuerArn']}")
            print(
                f"    AuthorizedAudiences: {', '.join(issuer['AuthorizedAudiences'])}"
            )


def filter_jwt_bearer_grants(grants_data):
    """
    Filters the grants with a 'GrantType' of value 'urn:ietf:params:oauth:grant-type:jwt-bearer'.

    Args:
        grants_data (dict): A dictionary containing the grants data.

    Returns:
        list: A list of grants with a 'GrantType' of value 'urn:ietf:params:oauth:grant-type:jwt-bearer'.
    """
    jwt_bearer_grants = []
    for grant in grants_data:
        if grant["GrantType"] == "urn:ietf:params:oauth:grant-type:jwt-bearer":
            jwt_bearer_grants.append(grant)
    return jwt_bearer_grants


def group_by_scope_and_account(application_scopes):
    scope_groups = {}

    for obj in application_scopes:
        scope = obj["Scope"]
        authorized_targets = obj["AuthorizedTargets"]

        if scope not in scope_groups:
            scope_groups[scope] = {"all_accounts": [], "account_groups": {}}

        if not authorized_targets:
            scope_groups[scope]["all_accounts"].append(
                "All current and future applications"
            )
        else:
            for target in authorized_targets:
                account_id = target.split(":")[4]
                if account_id not in scope_groups[scope]["account_groups"]:
                    scope_groups[scope]["account_groups"][account_id] = []
                scope_groups[scope]["account_groups"][account_id].append(target)

    for scope, scope_data in scope_groups.items():
        print_line(f"Scope: {scope}")

        if scope_data["all_accounts"]:
            print_line("All AWS Accounts of the organization")
            for target in scope_data["all_accounts"]:
                print_line(f"- {target}")
            print_line()

        for account_id, targets in scope_data["account_groups"].items():
            print_line(f"Account ID: {account_id}")
            for target in targets:
                print_line(f"- {target}")
            print_line()


def decode_jwt(token):
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


def print_check(text, status, output_function=click.echo):
    output_str = ""
    if status == "OK":
        output_str += f"{bcolors.OKGREEN}\N{check mark}{bcolors.ENDC}"
    elif status == "WARNING":
        output_str += f"{bcolors.WARNING}\N{warning sign}{bcolors.ENDC}"
    else:
        output_str += f"{bcolors.FAIL}\N{cross mark}{bcolors.ENDC}"

    output_str += f" {text}"
    output_function(output_str)

    return output_str


def print_line(text="", output_function=click.echo):
    output_function(text)


class bcolors:
    OKGREEN = "\033[92m"
    WARNING = "\033[93m"
    FAIL = "\033[91m"
    ENDC = "\033[0m"
    BOLD = "\033[1m"
