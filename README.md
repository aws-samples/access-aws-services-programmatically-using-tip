# Access AWS services programmatically using trusted identity propagation

This sample Python application demonstrates how you can access AWS services, such as Amazon S3 and Amazon Athena, using trusted identity propagation, an AWS IAM Identity Center feature that allows authorized access to AWS resources based on the user's identity context and securely shares the user's identity context with other AWS services.

The application also provides a [diagnostic tool](#trusted-token-issuer-diagnostic-utility) to help you verify your current setup.

## Getting Started

### Prerequisites

List of prerequisites needed to use this tool:

- Python 3.x
- AWS CLI
- An OAuth 2.0-based external identity provider configured as [trusted token issuer](https://docs.aws.amazon.com/singlesignon/latest/userguide/using-apps-with-trusted-token-issuer.html) with AWS IAM Identity Center. This sample code provides support for Okta, Entra ID, and Amazon Cognito but you can [implement additional providers](#implementing-additional-oauth-20-identity-providers).
- A [customer managed application](https://docs.aws.amazon.com/singlesignon/latest/userguide/trustedidentitypropagation-using-customermanagedapps-setup.html) configured to be used with [Amazon S3 Access Grants](https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-grants.html) and/or [Amazon Athena](https://docs.aws.amazon.com/athena/latest/ug/workgroups-identity-center.html), or any other AWS service that supports Trusted Identity Propagation (see [Trusted identity propagation use cases](https://docs.aws.amazon.com/singlesignon/latest/userguide/trustedidentitypropagation-integrations.html) in the AWS documentation).

Refer to the blog post [Access AWS services programmatically using trusted identity propagation](https://aws.amazon.com/blogs/security/access-aws-services-programmatically-using-trusted-identity-propagation/) to learn how to create a customer managed application.

### Security considerations

This application retrieves and stores locally the tokens issued by the identity provider, as well as temporary IAM credentials issued from the backend application and optionally by Amazon S3 Access Grants. By default, the information is stored in the local path `~/.aws_tip_cli` (can be configured with the environment variable `AWS_TIP_CLI`).

### Installation

Create a new Python Virtualenv and install the application:

```bash
python -m venv .venv
source .venv/bin/activate
pip install .
```

### Configuration of IAM roles

The application uses [OIDC federation](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_oidc.html) to use the token provided by the OAuth 2.0 identity provider you configure to assume an IAM role session. This IAM role session is used to first 
initiate the token exchange with the [customer managed application](https://docs.aws.amazon.com/singlesignon/latest/userguide/trustedidentitypropagation-using-customermanagedapps-setup.html) you create in AWS IAM Identity Center. If the exchange is successful, the token 
returned by IAM Identity Center is used to create the [identity-enhanced IAM role session](https://docs.aws.amazon.com/singlesignon/latest/userguide/trusted-identity-propagation-using-aws-managed-applications.html#trustedidentitypropagation-identity-enhanced-iam-role-sessions). 

You can see the code that performs the steps above in the [auth_loader.py](src/utils/auth_loader.py).

The application can generate a CloudFormation template that deploys the required components given the URL of your IdP and the value of the aud attribute of the token. Those are the same parameters you use also to configure the Trusted Identity Propagation feature in IAM Identity Center.
For example, if you use Okta and your source Okta application URL is `https://dev-123456789.okta.com/oauth2/default`, the `aud` value of the tokens issued is `abcdefghij1234567890` and the [certificate thumbprint](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_create_oidc_verify-thumbprint.html) is `55357933a7310d2db90c3fa1ed0970a7bb34ed39`, you can use the following command:

```bash
tip-cli configure generate-cfn-template https://dev-123456789.okta.com/oauth2/default abcdefghij1234567890 55357933a7310d2db90c3fa1ed0970a7bb34ed39 > ~/idp-template.yaml
```

_The certificate thumbprint can be omitted, and the application will try to extract the thumbprint automatically. If you encounter errors when using the application and you used automatic thumbprint generation, consider verifying the value of the thumbprint._

Review the CloudFormation template generated and deploy it. 

Note the CloudFormation output parameters `OIDCRoleArn` and `IdEnhancedRoleArn` as you will use to configure the application in the next step.

Remember to update the IAM Identity Center [customer managed application credentials](https://docs.aws.amazon.com/singlesignon/latest/userguide/trustedidentitypropagation-using-customermanagedapps-setup.html#customermanagedapps-trusted-identity-propagation-set-up-your-own-app-OAuth2-specify-application-credentials) to allow the role `OIDCRoleArn` to perform the action `sso-oauth:CreateTokenWithIAM`.

### Configuration of the application

1. Configure the CLI with your IdP information, the ARN of the custom application you created in IAM Identity Center, and the ARNs of the role described above:

```bash
tip-cli configure idp
```

2. Verify that your settings are correct by authenticating with your configured IdP:

```bash
tip-cli auth
```

3. (optional) Run the [diagnostic tool](#trusted-token-issuer-diagnostic-utility) to verify the configuration of your customer managed application and JWT token:

```bash
tip-cli diag
```

4. Retrieve an [Identity-enhanced IAM role session](https://docs.aws.amazon.com/singlesignon/latest/userguide/trusted-identity-propagation-using-aws-managed-applications.html#trustedidentitypropagation-identity-enhanced-iam-role-sessions):

```bash
tip-cli auth get-iam-credentials
```

5. Configure your AWS CLI to use the application as a [credentials source](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sourcing-external.html):


```ini
[profile my-tti-profile]
output=json
region=eu-west-1
credential_process=tip-cli auth get-iam-credentials
```

6. Verify that the AWS CLI can use the application correctly:

```bash
aws sts get-caller-identity --profile my-tti-profile
```

You should see a successful response, and a `UserId` that is suffixed by `tip-<AWS-IDC-USERID>`, where `<AWS-IDC-USERID>` represents the unique ID of the IAM Identity Center user.

### Usage with AWS services

You can now access any AWS service that supports the trusted identity propagation feature from the AWS CLI. You will need to configure each service individually, and configure your AWS IAM Identity Center Custom Application accordingly.
For example, you can query Amazon Athena tables as follows:

```bash
QUERY_EXECUTION_ID=$(aws athena start-query-execution \
    --query-string "SELECT * FROM db_tip.table_example LIMIT 3" \
    --work-group "tip-workgroup" \
    --profile my-tti-profile \
    --output text \
    --query 'QueryExecutionId')

aws athena get-query-results \
    --query-execution-id $QUERY_EXECUTION_ID \
    --profile my-tti-profile \
    --output text
```

If your IAM Identity Center user has also Amazon Q business applications, you can access the Amazon Q business API. For example, to retrieve all conversations of the user for an Amazon Q business application with the ID `a1b2c3d4-5678-90ab-cdef-EXAMPLE11111`, use:

```
aws qbusiness list-conversations --application-id a1b2c3d4-5678-90ab-cdef-EXAMPLE11111 --profile my-tti-profile
```

You can also start new conversations, for example:

```
aws qbusiness chat-sync --application-id a1b2c3d4-5678-90ab-cdef-EXAMPLE11111 --chat-mode RETRIEVAL_MODE --user-message "What is Amazon Q business?"
```

### Usage with Amazon S3

The application also provides a set of tools to use S3 Access Grants by abstracting the API calls to the S3 API [get-data-access](https://docs.aws.amazon.com/AmazonS3/latest/API/API_control_GetDataAccess.html).
Configure access to S3 Access Grants by creating additional AWS CLI profiles. For example, to configure access through S3 Access Grants to the path `s3://<my-test-bucket-with-path>`, add the following profile to the AWS CLI:

```ini
[profile my-tti-profile-s3ag]
output=json
region=eu-west-1
credential_process=tip-cli s3ag get-data-access s3://<my-test-bucket-with-path> --permission READWRITE
```

You can then access the S3 bucket as follows:

```bash
aws s3 ls s3://<my-test-bucket-with-path> --profile my-tti-profile-s3ag
```

The request will succeed if there is an Amazon S3 Access Grant matching for the user and the requested path. Use `tip-cli s3ag --help` to see all options.

## Trusted Token Issuer diagnostic utility

This application also provides a diagnostic tool to verify the setup of an AWS IAM Identity Center customer managed application. The diagnostic verifies the trusted token issuer configuration against a given JWT.
It can also use the current setup to retrieve a JWT from your IdP.

The diagnostic tool requires the following IAM permissions:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "sso:DescribeApplication",
                "sso:GetApplicationAssignmentConfiguration",
                "sso:GetApplicationAuthenticationMethod",
                "sso:ListApplicationGrants",
                "sso:ListApplicationAccessScopes",
                "sso:DescribeTrustedTokenIssuer",
                "sso:DescribeInstance",
                "identitystore:GetUserId",
                "identitystore:DescribeUser"
            ],
            "Resource": "*"
        }
    ]
}
```

To run the diagnostic with your current configuration use:

```bash
tip-cli diag
```

You can also diagnose any customer managed application and JWT by passing them as parameters to the command:

```bash
tip-cli diag -j <idp_sourced_jwt_token> -a <token_exchange_application_arn>
```

## Advanced Usage

- Configure command with inline parameters:

```
tip-cli configure --idp okta --config '{"token_exchange_application_arn": "<token_exchange_application_arn>", "oidc_role_arn": "<oidc_role_arn>",  "id_enhanced_role_arn": "<id_enhanced_role_arn>", "okta_url": "https://dev-123456789.okta.com/oauth2/default", "okta_client_id": "0oEXAMPLE"}'
```

- Configure command also accepts JSON file as a parameter:

```
tip-cli configure --idp okta --config file.json
```

- Get S3 Access Grants permission:

```
tip-cli s3ag get-data-access --account-id 123412341234 --permission READ s3://example-bucket/prefix/
```

- List current S3 Access Grants credentials:

```
tip-cli s3ag list-credentials
```

- Force refresh of Token:

```
tip-cli auth refresh-token
```

### Implementing additional OAuth 2.0 Identity Providers

This code includes integrations with Okta, Entra ID, and Amazon Cognito as trusted token issuers. You can integrate any OAuth 2.0-based identity provider by extending the class [base_auth.py](src/auth/base_auth.py).

## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This library is licensed under the MIT-0 License. See the LICENSE file.
