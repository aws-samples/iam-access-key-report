## IAM Access Key Report

This is a simple python script that will enumerate data about all active IAM access keys across an AWS Organization and will enrich each key with account tag information.

The output of the script is a CSV file that can then be filtered based on the tag information associated with the keys.

This allow us to focus on access keys that are used in things like 'Environment:Production' accounts or in accounts that are labelled with 'DataClassification:Restricted'.

In addition, the script performs some basic security checks of the IAM policies of the user accounts the access keys are attached to. It will tell you if a key has administrative permissions or 
is able to read your data in Amazon S3, Amazon RDS, and Amazon DynamoDB.

### Usage
You will need the following permissions in the AWS organization management account or an account that is a delegated administrator for an AWS service:
- organizations:ListTagsForResources
- organizations:ListOrganizationalUnitsForParents
- organizations:ListAccountsForParents
- organizations:DescribeOrganizationalUnits
- organizations:ListRoots

You will also need to provide the name of a role that the script can use to assume into each account in the organization and retrieve access key information.
The role in each account must have the following permissions:
- iam:CreateCredentialReport
- iam:GetCredentialReport

Basic usage of the script:
`$ iam-access-key-report.py [-h] [-m METADATA_OUTPUT | -i METADATA_INPUT] [-r ROLE] [-p PROFILE] csv_output`

`-h`  
shows a help messages and exits

`-m filename`
will pull all account tags, write them to a file, and then exit. This is if you just want the tag information or if you dont want to have to keep pulling it each time the tool is run

`-i filename`
you can load tag information that has previously been extracted by using (-m)

`-r role`
provide a role name that can be used to assume into each account. the role will need to already exist or you will need to create it.

`p profile`
the name of a profile configured through the AWS CLI (if you dont specify a profile, the script will use whatever local credentials it can find)

`csv_output`
the output file generated in CSV format




## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This library is licensed under the MIT-0 License. See the LICENSE file.

