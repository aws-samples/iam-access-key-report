#
# Library for getting all account numbers, names, tags and OU from AWS Organization
# Returns a DataFrame
#
import logging
import boto3
import json

from botocore.exceptions import ClientError

def get_account_metadata(session=None):
    
    # if we don't get a session, create one
    if session is None:
        session = boto3.Session()
    
    organizations = session.client('organizations')
    
    def get_org_root():
        response = organizations.list_roots()
        roots = response.get("Roots", None)
    
        if not roots:
            return None
    
        return roots[0]
    
    def get_tags(id):
        paginator = organizations.get_paginator("list_tags_for_resource")
        responses = paginator.paginate(ResourceId=id)
    
        tags = {}
        for response in responses:
            for tag in response.get("Tags", []):
                tags[tag["Key"]] = tag["Value"]
    
        return tags
    
    def get_child_orgunits(parent_id):
        paginator = organizations.get_paginator("list_organizational_units_for_parent")
        responses = paginator.paginate(ParentId=parent_id)
    
        orgunits = []
        for response in responses:
            orgunits += response.get("OrganizationalUnits", [])
    
        return orgunits
        
    def get_child_accounts(parent_id):
        paginator = organizations.get_paginator("list_accounts_for_parent")
        responses = paginator.paginate(ParentId=parent_id)
    
        accounts = []
        for response in responses:
            accounts += response.get("Accounts", [])
    
        return accounts
    
    accounts_list = {}
    accounts_list['Accounts'] = []
    
    def walk_org(orgunit_id, depth):
        child_accounts = get_child_accounts(orgunit_id)
    
        for account in child_accounts:
            child_account_id = account["Id"]
            tags = get_tags(child_account_id)
            
            account_info = {}
            account_info['Id'] = child_account_id
            account_info['OU'] = depth
            account_info['Name'] = account['Name']
            account_info['Tags'] = tags
            logging.info("Found account: "+json.dumps(account_info))
            accounts_list['Accounts'].append(account_info)
    
        child_orgunits = get_child_orgunits(orgunit_id)
        for orgunit in child_orgunits:
            child_orgunit_id = orgunit["Id"]
    
            # Lookup orgunit details
            response = organizations.describe_organizational_unit(OrganizationalUnitId=child_orgunit_id)
            name = response["OrganizationalUnit"]["Name"]
            tags = get_tags(child_orgunit_id)
            
            # Walk rest of org
            walk_org(child_orgunit_id, depth+',OU='+name)
              
    org_root = get_org_root()
    org_root_id = org_root.get("Id")
    walk_org(org_root_id, "OU=root")
    
    return accounts_list
