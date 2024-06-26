AWSTemplateFormatVersion: '2010-09-09'
Description: Deploy an IAM OIDC Provider and roles that can be used with Trusted Identity Propagation

Resources:
  OIDCProvider:
    Type: AWS::IAM::OIDCProvider
    Properties:
      ThumbprintList: ["{{ oidc_provider_thumbprint }}"]
      Url: "{{ oidc_provider_url }}"
      ClientIdList:
        - "{{ oidc_provider_aud }}"

  OIDCRole:
    Type: AWS::IAM::Role
    Properties:
      MaxSessionDuration: 3600
      AssumeRolePolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Effect: Allow
            Principal:
              Federated: !GetAtt OIDCProvider.Arn
            Action: "sts:AssumeRoleWithWebIdentity"
            Condition:
              StringEquals:
                "{{ oidc_provider_iam_name }}:aud": "{{ oidc_provider_aud }}"
      Policies:
        - PolicyName: sso-oauth
          PolicyDocument:
            Version: "2012-10-17"
            Statement:
              - Effect: Allow
                Action: 'sso-oauth:CreateTokenWithIAM'
                Resource: '*'

  IdEnhancedRole:
    Type: AWS::IAM::Role
    Properties:
      MaxSessionDuration: 3600
      AssumeRolePolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Effect: Allow
            Principal:
              AWS: !GetAtt OIDCRole.Arn
            Action: 
              - "sts:AssumeRole"
              - "sts:SetContext"
      Policies:
        - PolicyName: athena-query
          PolicyDocument:
            Version: "2012-10-17"
            Statement:
              - Effect: Allow
                Action:
                  - "athena:StartQueryExecution"
                  - "athena:GetQueryExecution"
                  - "athena:GetQueryResults"
                  - "athena:StopQueryExecution"
                  - "athena:GetWorkGroup"
                  - "athena:GetQueryResultsStream"
                  - "athena:ListDataCatalogs"
                  - "athena:ListDatabases"
                  - "athena:ListWorkGroups"
                Resource: '*'
        - PolicyName: s3ag
          PolicyDocument:
            Version: "2012-10-17"
            Statement:
              - Effect: Allow
                Action:
                  - "s3:GetDataAccess"
                Resource: '*'

Outputs:
  OIDCRoleArn:
    Description: The ARN of the IAM role used in the initial token exchange with Identity Center
    Value: !GetAtt OIDCRole.Arn

  IdEnhancedRoleArn:
    Description: The ARN of the IAM role used to create the identity-enhanced IAM role session
    Value: !GetAtt IdEnhancedRole.Arn
