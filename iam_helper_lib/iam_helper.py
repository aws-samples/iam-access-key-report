import logging
import boto3
import pandas as pd
from io import StringIO

from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)

def get_user_policies(user_arn):
    pass

# enumerates managed policies and appends to user object
def get_managed_policies(session, user):
    iam = session.client("iam")
    user['ManagedPolicies'] = []

    #managed_policies_output = {'policies': []};

    paginator = iam.get_paginator('list_attached_user_policies')
    page_iterator = paginator.paginate(UserName=user['UserName'])
    for page in page_iterator:
        # get policy versions
        for policy in page['AttachedPolicies']:
            policy_details = {}
            policy_details['Name'] = policy['PolicyName']
            policy_details['PolicyArn'] = policy['PolicyArn']
            policy_info = iam.get_policy(PolicyArn=policy['PolicyArn'])
            raw_policy = iam.get_policy_version(PolicyArn=policy['PolicyArn'], VersionId=policy_info['Policy']['DefaultVersionId'])
            policy_details['RawPolicy'] = raw_policy['PolicyVersion']
            user['ManagedPolicies'].append(policy_details)

    return user


    
def get_group():
    pass


def generate_credential_report(session):
    """
    Starts generation of a credentials report about the current account. After
    calling this function to generate the report, call get_credential_report
    to get the latest report. A new report can be generated a minimum of four hours
    after the last one was generated.
    """
    try:
        iam = session.client("iam")
        response = iam.generate_credential_report()
        logger.info("Generating credentials report for your account. "
                    "Current state is %s.", response['State'])
    except ClientError:
        logger.exception("Couldn't generate a credentials report for your account.")
        raise
    else:
        return response
        
def get_credential_report(session):
    """
    Gets the most recently generated credentials report about the current account.
    :return: The credentials report.
    """
    try:
        iam = session.client("iam")
        response = iam.get_credential_report()
        logger.debug(response['Content'])
    except ClientError:
        logger.exception("Couldn't get credentials report.")
        raise
    else:
        return response['Content']

def get_active_access_keys(session):
    
    # create the credential report if doesn't exist
    generate_credential_report(session)
    
    # pull the report
    report = get_credential_report(session)
    
    # load it into a df
    csvStringIO = StringIO(report.decode("utf-8"))
    df = pd.read_csv(csvStringIO, sep=",")
    
    # check for active access keys
    df = df.query("access_key_2_active | access_key_1_active")
    
    return df
    
def get_group_policies(session, user):
    
    client = session.client("iam")
    
    user['Groups'] = []
    user['Policies'] = []
    try:
        policies = []

        ## Get groups that the user is in
        try:
            res = client.list_groups_for_user(
                UserName=user['UserName']
            )
            user['Groups'] = res['Groups']
            print(res)
            while 'IsTruncated' in res and res['IsTruncated'] is True:
                res = client.list_groups_for_user(
                    UserName=user['UserName'],
                    Marker=res['Marker']
                )
                user['Groups'] += res['Groups']
        except Exception as e:
            print('List groups for user failed: {}'.format(e))
            user['PermissionsConfirmed'] = False

        ## Get inline and attached group policies
        for group in user['Groups']:
            group['Policies'] = []
            ## Get inline group policies
            try:
                res = client.list_group_policies(
                    GroupName=group['GroupName']
                )
                policies = res['PolicyNames']
                while 'IsTruncated' in res and res['IsTruncated'] is True:
                    res = client.list_group_policies(
                        GroupName=group['GroupName'],
                        Marker=res['Marker']
                    )
                    policies += res['PolicyNames']
            except Exception as e:
                print('List group policies failed: {}'.format(e))
                user['PermissionsConfirmed'] = False
            # Get document for each inline policy
            for policy in policies:
                print("hi")
                group['Policies'].append({ # Add policies to list of policies for this group
                    'PolicyName': policy
                })
                try:
                    document = client.get_group_policy(
                        GroupName=group['GroupName'],
                        PolicyName=policy
                    )['PolicyDocument']
                except Exception as e:
                    print('Get group policy failed: {}'.format(e))
                    user['PermissionsConfirmed'] = False
                user = parse_document(document, user)

            ## Get attached group policies
            attached_policies = []
            try:
                res = client.list_attached_group_policies(
                    GroupName=group['GroupName']
                )
                attached_policies = res['AttachedPolicies']
                while 'IsTruncated' in res and res['IsTruncated'] is True:
                    res = client.list_attached_group_policies(
                        GroupName=group['GroupName'],
                        Marker=res['Marker']
                    )
                    attached_policies += res['AttachedPolicies']
                group['Policies'] += attached_policies
                print("here")
            except Exception as e:
                print('List attached group policies failed: {}'.format(e))
                user['PermissionsConfirmed'] = False
                
            user = parse_attached_policies(client, attached_policies, user)
    except Exception as e:
        print('Error, skipping user {}:\n{}'.format(user['UserName'], e))
        
    return user
    
# Pull permissions from each policy document
def parse_attached_policies(client, attached_policies, user):
    for policy in attached_policies:
        document = get_attached_policy(client, policy['PolicyArn'])
        if document is False:
            user['PermissionsConfirmed'] = False
        else:
            print("nothing to see")
            user = parse_document(document, user)
    return user

# Get the policy document of an attached policy
def get_attached_policy(client, policy_arn):
    try:
        policy = client.get_policy(
            PolicyArn=policy_arn
        )['Policy']
        version = policy['DefaultVersionId']
        can_get = True
    except Exception as e:
        print('Get policy failed: {}'.format(e))
        return False

    try:
        if can_get is True:
            document = client.get_policy_version(
                PolicyArn=policy_arn,
                VersionId=version
            )['PolicyVersion']['Document']
            return document
    except Exception as e:
        print('Get policy version failed: {}'.format(e))
        return False
        
def parse_document(document, user):
    if type(document['Statement']) is dict:
        document['Statement'] = [document['Statement']]
    for statement in document['Statement']:
        if statement['Effect'] == 'Allow':
            if 'Action' in statement and type(statement['Action']) is list: # Check if the action is a single action (str) or multiple (list)
                statement['Action'] = list(set(statement['Action'])) # Remove duplicates to stop the circular reference JSON error
                for action in statement['Action']:
                    if action in user['Permissions']['Allow']:
                        if type(statement['Resource']) is list:
                            user['Permissions']['Allow'][action] += statement['Resource']
                        else:
                            user['Permissions']['Allow'][action].append(statement['Resource'])
                    else:
                        if type(statement['Resource']) is list:
                            user['Permissions']['Allow'][action] = statement['Resource']
                        else:
                            user['Permissions']['Allow'][action] = [statement['Resource']]
                    user['Permissions']['Allow'][action] = list(set(user['Permissions']['Allow'][action])) # Remove duplicate resources
            elif 'Action' in statement and type(statement['Action']) is str:
                if statement['Action'] in user['Permissions']['Allow']:
                    if type(statement['Resource']) is list:
                        user['Permissions']['Allow'][statement['Action']] += statement['Resource']
                    else:
                        user['Permissions']['Allow'][statement['Action']].append(statement['Resource'])
                else:
                    if type(statement['Resource']) is list:
                        user['Permissions']['Allow'][statement['Action']] = statement['Resource']
                    else:
                        user['Permissions']['Allow'][statement['Action']] = [statement['Resource']] # Make sure that resources are always arrays
                user['Permissions']['Allow'][statement['Action']] = list(set(user['Permissions']['Allow'][statement['Action']])) # Remove duplicate resources
            if 'NotAction' in statement and type(statement['NotAction']) is list: # NotAction is reverse, so allowing a NotAction is denying that action basically
                statement['NotAction'] = list(set(statement['NotAction'])) # Remove duplicates to stop the circular reference JSON error
                for not_action in statement['NotAction']:
                    if not_action in user['Permissions']['Deny']:
                        if type(statement['Resource']) is list:
                            user['Permissions']['Deny'][not_action] += statement['Resource']
                        else:
                            user['Permissions']['Deny'][not_action].append(statement['Resource'])
                    else:
                        if type(statement['Resource']) is list:
                            user['Permissions']['Deny'][not_action] = statement['Resource']
                        else:
                            user['Permissions']['Deny'][not_action] = [statement['Resource']]
                    user['Permissions']['Deny'][not_action] = list(set(user['Permissions']['Deny'][not_action])) # Remove duplicate resources
            elif 'NotAction' in statement and type(statement['NotAction']) is str:
                if statement['NotAction'] in user['Permissions']['Deny']:
                    if type(statement['Resource']) is list:
                        user['Permissions']['Deny'][statement['NotAction']] += statement['Resource']
                    else:
                        user['Permissions']['Deny'][statement['NotAction']].append(statement['Resource'])
                else:
                    if type(statement['Resource']) is list:
                        user['Permissions']['Deny'][statement['NotAction']] = statement['Resource']
                    else:
                        user['Permissions']['Deny'][statement['NotAction']] = [statement['Resource']] # Make sure that resources are always arrays
                user['Permissions']['Deny'][statement['NotAction']] = list(set(user['Permissions']['Deny'][statement['NotAction']])) # Remove duplicate resources
        if statement['Effect'] == 'Deny':
            if 'Action' in statement and type(statement['Action']) is list:
                statement['Action'] = list(set(statement['Action'])) # Remove duplicates to stop the circular reference JSON error
                for action in statement['Action']:
                    if action in user['Permissions']['Deny']:
                        if type(statement['Resource']) is list:
                            user['Permissions']['Deny'][action] += statement['Resource']
                        else:
                            user['Permissions']['Deny'][action].append(statement['Resource'])
                    else:
                        if type(statement['Resource']) is list:
                            user['Permissions']['Deny'][action] = statement['Resource']
                        else:
                            user['Permissions']['Deny'][action] = [statement['Resource']]
                    user['Permissions']['Deny'][action] = list(set(user['Permissions']['Deny'][action])) # Remove duplicate resources
            elif 'Action' in statement and type(statement['Action']) is str:
                if statement['Action'] in user['Permissions']['Deny']:
                    if type(statement['Resource']) is list:
                        user['Permissions']['Deny'][statement['Action']] += statement['Resource']
                    else:
                        user['Permissions']['Deny'][statement['Action']].append(statement['Resource'])
                else:
                    if type(statement['Resource']) is list:
                        user['Permissions']['Deny'][statement['Action']] = statement['Resource']
                    else:
                        user['Permissions']['Deny'][statement['Action']] = [statement['Resource']] # Make sure that resources are always arrays
                user['Permissions']['Deny'][statement['Action']] = list(set(user['Permissions']['Deny'][statement['Action']])) # Remove duplicate resources
            if 'NotAction' in statement and type(statement['NotAction']) is list: # NotAction is reverse, so allowing a NotAction is denying that action basically
                statement['NotAction'] = list(set(statement['NotAction'])) # Remove duplicates to stop the circular reference JSON error
                for not_action in statement['NotAction']:
                    if not_action in user['Permissions']['Allow']:
                        if type(statement['Resource']) is list:
                            user['Permissions']['Allow'][not_action] += statement['Resource']
                        else:
                            user['Permissions']['Allow'][not_action].append(statement['Resource'])
                    else:
                        if type(statement['Resource']) is list:
                            user['Permissions']['Allow'][not_action] = statement['Resource']
                        else:
                            user['Permissions']['Allow'][not_action] = [statement['Resource']]
                    user['Permissions']['Allow'][not_action] = list(set(user['Permissions']['Allow'][not_action])) # Remove duplicate resources
            elif 'NotAction' in statement and type(statement['NotAction']) is str:
                if statement['NotAction'] in user['Permissions']['Allow']:
                    if type(statement['Resource']) is list:
                        user['Permissions']['Allow'][statement['NotAction']] += statement['Resource']
                    else:
                        user['Permissions']['Allow'][statement['NotAction']].append(statement['Resource'])
                else:
                    if type(statement['Resource']) is list:
                        user['Permissions']['Allow'][statement['NotAction']] = statement['Resource']
                    else:
                        user['Permissions']['Allow'][statement['NotAction']] = [statement['Resource']] # Make sure that resources are always arrays
                user['Permissions']['Allow'][statement['NotAction']] = list(set(user['Permissions']['Allow'][statement['NotAction']])) # Remove duplicate resources
    return user
