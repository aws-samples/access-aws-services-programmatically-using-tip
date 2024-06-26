import json
import logging

import boto3
import click

from ..utils.app_config import AppConfig
from ..utils.auth_loader import load_auth_class
from ..utils.diag_utils import (decode_jwt, filter_jwt_bearer_grants,
                                filter_token_issuer_arns_by_audience,
                                get_idp_token, group_by_scope_and_account,
                                parse_application_arn, print_check, print_line)

logger = logging.getLogger(__name__)


@click.group(invoke_without_command=True)
@click.pass_context
@click.option("--help", is_flag=True, default=False, help="Show this message and exit.")
@click.option(
    "-j",
    "--jwt",
    required=False,
    help="The JWT token to use to run the diagnostic - if omitted the tool tries to use the token already configured with your IdP",
)
@click.option(
    "-a",
    "--customer-managed-application-arn",
    required=False,
    help="The ARN of the customer managed application that is used to perform the token exchange - if omitted the tool tries to use the one already configured",
)
def diag(ctx, help, jwt, customer_managed_application_arn):
    """Run diagnostic of configuration of a customer managed application configured with the trusted token issuer feature"""
    if help:
        click.echo(ctx.get_help())
        ctx.exit()

    if not jwt and not customer_managed_application_arn:
        app_config, auth_instance, token_exchange_application_arn = (
            load_config_and_auth(ctx)
        )
        jwt_token = get_idp_token(auth_instance)
    else:
        token_exchange_application_arn = (
            customer_managed_application_arn
            if customer_managed_application_arn
            else None
        )
        jwt_token = jwt

    try:
        decoded_jwt = decode_jwt(jwt_token)
    except Exception as e:
        logger.error(f"Failed to decode JWT token: {e}")
        click.exit(1)

    idc_arn = parse_application_arn(token_exchange_application_arn)

    sso_admin_client = boto3.client("sso-admin")

    idc_customer_managed_application_assignment = (
        sso_admin_client.get_application_assignment_configuration(
            ApplicationArn=token_exchange_application_arn
        )
    )
    customer_managed_application_requires_assignment = (
        idc_customer_managed_application_assignment["AssignmentRequired"]
    )

    check_basic_configuration(sso_admin_client, token_exchange_application_arn)
    check_resource_policy(sso_admin_client, token_exchange_application_arn)
    matching_tti = check_tti_configuration(
        sso_admin_client, token_exchange_application_arn, decoded_jwt
    )
    check_tti_jwt_matching(
        sso_admin_client,
        token_exchange_application_arn,
        decoded_jwt,
        matching_tti,
        idc_arn,
        customer_managed_application_requires_assignment,
    )
    check_scopes(sso_admin_client, token_exchange_application_arn)

    print_line(
        "Diagnostic complete - note that the diagnostic tool does not verify the JWT signature."
    )


def check_basic_configuration(sso_admin_client, token_exchange_application_arn):
    idc_customer_managed_application = sso_admin_client.describe_application(
        ApplicationArn=token_exchange_application_arn
    )

    print_line("CHECK BASIC CONFIGURATION")
    if idc_customer_managed_application["Status"] == "ENABLED":
        print_check("Identity Center Customer Managed Application is enabled", "OK")
    else:
        print_check(
            "Identity Center Customer Managed Application is NOT enabled", "FAIL"
        )

    if (
        idc_customer_managed_application["ApplicationProviderArn"]
        == "arn:aws:sso::aws:applicationProvider/custom"
    ):
        print_check(
            "The selected Identity application is a Customer Managed Application", "OK"
        )
    else:
        print_check(
            "The selected Identity application is a NOT a Customer Managed Application - a Customer Managed Application is required to use the trusted token issuer feature",
            "FAIL",
        )
    print_line("")


def check_resource_policy(sso_admin_client, token_exchange_application_arn):
    print_line("CHECK CUSTOMER MANAGED APPLICATION RESOURCE POLICY")
    try:
        idc_customer_managed_application_resource_policy = (
            sso_admin_client.get_application_authentication_method(
                ApplicationArn=token_exchange_application_arn,
                AuthenticationMethodType="IAM",
            )
        )
        policy = idc_customer_managed_application_resource_policy[
            "AuthenticationMethod"
        ]["Iam"]["ActorPolicy"]
        print_check(
            'Identity Center Customer Managed Application has a resource policy - manually verify below that the action "sso-oauth:CreateTokenWithIAM" is allowed to the principal (role ARN) that will perform the token exchange',
            "OK",
        )
        print(json.dumps(policy, indent=4))
    except sso_admin_client.exceptions.ResourceNotFoundException as e:
        print_check(
            'Identity Center Customer Managed Application Resource Policy is missing - the resource policy must be present and explicitly allow the action "sso-oauth:CreateTokenWithIAM" to the principal (role ARN) that will perform the token exchange'
        )
    print_line("")


def check_tti_configuration(
    sso_admin_client, token_exchange_application_arn, decoded_jwt
):
    application_grants = sso_admin_client.list_application_grants(
        ApplicationArn=token_exchange_application_arn
    )
    jwt_bearer_grants = filter_jwt_bearer_grants(application_grants["Grants"])
    if not jwt_bearer_grants:
        print_check(
            "No trusted token issuer configured with the customer managed application - you must configure at least one trusted identity token issuer with the customer managed application",
            "FAIL",
        )

    try:
        audience = decoded_jwt["aud"]
    except KeyError:
        print_check(
            "The JWT does not contain the aud attribute - you must use JWT that contains an aud attribute",
            "FAIL",
        )

    # CHECK MATCHING USER FOR TTI WITH AUD
    matching_tti = filter_token_issuer_arns_by_audience(jwt_bearer_grants, audience)
    if matching_tti:
        print_check(
            f"Found {len(matching_tti)} trusted token issuer(s) configured in the customer managed application with matching aud value {audience}",
            "OK",
        )
    else:
        print_check(
            f"No matching trusted token issuer found for the audience {audience} - verify that the configured trusted token issuer for the customer managed application contains the same aud value as the provided JWT",
            "FAIL",
        )
    print_line("")
    return matching_tti


def check_tti_jwt_matching(
    sso_admin_client,
    token_exchange_application_arn,
    decoded_jwt,
    matching_tti,
    idc_arn,
    customer_managed_application_requires_assignment,
):
    print_line("CHECK MATCHING JWT WITH IAM IDENTITY CENTER IDENTITY STORE")
    iss = decoded_jwt["iss"]
    for tti_arn in matching_tti:
        tti_describe = sso_admin_client.describe_trusted_token_issuer(
            TrustedTokenIssuerArn=tti_arn
        )
        if (
            tti_describe["TrustedTokenIssuerConfiguration"]["OidcJwtConfiguration"][
                "IssuerUrl"
            ]
            == iss
        ):
            claim_attribute_path = tti_describe["TrustedTokenIssuerConfiguration"][
                "OidcJwtConfiguration"
            ]["ClaimAttributePath"]
            id_store_attribute_path = tti_describe["TrustedTokenIssuerConfiguration"][
                "OidcJwtConfiguration"
            ]["IdentityStoreAttributePath"]

            if claim_attribute_path not in decoded_jwt:
                print_check(
                    f"The trusted token issuer {tti_describe['TrustedTokenIssuerArn']} is configured with the application and matches the iss and aud values of the given JWT - but the JWT is missing the configured source attribute {claim_attribute_path}. Review the configuration of the trusted token issuer in the AWS IAM Identity Center settings page",
                    "FAIL",
                )
            else:
                print_check(
                    f"The trusted token issuer configured source claim attribute {claim_attribute_path} is present in the JWT",
                    "OK",
                )
                idc_arn_describe = sso_admin_client.describe_instance(
                    InstanceArn=idc_arn
                )

                identity_store_client = boto3.client("identitystore")
                try:
                    user_search_result = identity_store_client.get_user_id(
                        IdentityStoreId=idc_arn_describe["IdentityStoreId"],
                        AlternateIdentifier={
                            "UniqueAttribute": {
                                "AttributePath": id_store_attribute_path,
                                "AttributeValue": decoded_jwt[claim_attribute_path],
                            }
                        },
                    )

                    user_id = user_search_result["UserId"]
                    print_check(
                        f"Found user ID {user_id} with matching attribute name {id_store_attribute_path} in IAM Identity Center identity store",
                        "OK",
                    )

                    describe_user_result = identity_store_client.describe_user(
                        IdentityStoreId=idc_arn_describe["IdentityStoreId"],
                        UserId=user_id,
                    )

                    if (
                        "ExternalIds" not in describe_user_result
                        or not describe_user_result["ExternalIds"]
                    ):
                        print_check(
                            f"The user {decoded_jwt[claim_attribute_path]} seems to have been created manually. If you are using an external identity provider, it is recommended to use SCIM to import users and groups",
                            "WARNING",
                        )

                    if customer_managed_application_requires_assignment:
                        list_application_assignement_for_user = (
                            sso_admin_client.list_application_assignments_for_principal(
                                Filter={
                                    "ApplicationArn": token_exchange_application_arn
                                },
                                InstanceArn=idc_arn,
                                PrincipalId=user_id,
                                PrincipalType="USER",
                            )
                        )
                        if list_application_assignement_for_user[
                            "ApplicationAssignments"
                        ]:
                            print_check(
                                f"User {decoded_jwt[claim_attribute_path]} is assigned to the customer managed application application",
                                "OK",
                            )
                        else:
                            print_check(
                                f"The customer managed application requires manual user assignment and the user {decoded_jwt[claim_attribute_path]} is not assigned to the application - manually verify group assignment",
                                "WARNING",
                            )
                except identity_store_client.exceptions.ResourceNotFoundException as e:
                    print_check(
                        f"No matching user with attribute key `{id_store_attribute_path}` and value `{decoded_jwt[claim_attribute_path]}` - check that the user exists in the IAM Identity Center identity store and that the trusted token issuer configuration is correct.",
                        "FAIL",
                    )
            break

    print_line("")


def check_scopes(sso_admin_client, token_exchange_application_arn):
    print_line(
        "CHECK CUSTOMER MANAGED APPLICATION SCOPES AND TRUSTED IDENTITY PROPAGATION WITH AWS MANAGED APPLICATIONS"
    )
    application_scopes = sso_admin_client.list_application_access_scopes(
        ApplicationArn=token_exchange_application_arn
    )

    if application_scopes["Scopes"]:
        print_check(
            "The customer managed application has scopes configured. Manually verify that the AWS IAM role you use to create the identity-enhanced session has the required IAM permissions",
            "OK",
        )
        print_line("Authorized AWS applications and scopes:")
        group_by_scope_and_account(application_scopes["Scopes"])
    else:
        print_check(
            "No scopes are configured for the customer managed application - you must configure at least one scope for the customer managed application",
            "FAIL",
        )
    print_line("")


def load_config_and_auth(ctx):
    app_config = ctx.obj.setdefault("app_config", AppConfig())
    app_config = ctx.obj["app_config"]
    if "idp" not in app_config.config:
        click.error("Missing configuration - run configure first")
        exit(1)

    ctx.obj["auth_instance"] = load_auth_class(app_config, app_config.config["idp"])
    token_exchange_application_arn = app_config.config["token_exchange_application_arn"]
    auth_instance = ctx.obj["auth_instance"]
    return app_config, auth_instance, token_exchange_application_arn
