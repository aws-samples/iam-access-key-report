# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

import boto3
import logging
import pandas as pd
import argparse
import sys
import json

from iam_helper_lib import iam_helper
from account_metadata_lib import account_metadata
from botocore.exceptions import ClientError

# stop traceback when we can't assume into an account
sys.tracebacklimit = 0

# set up logging
logger = logging.getLogger(__name__)
logging.basicConfig(
    format='%(asctime)s %(message)s',
    level=logging.INFO,
    datefmt='%Y-%m-%d %H:%M:%S'
)

def main():

    parser = argparse.ArgumentParser(description="Simple script used to enumerate IAM access key information and enrich it with account tags from AWS Organizations")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-s", "--metadata-save", type=str, help="Save account metadata to this file and do nothing else")
    group.add_argument("-l", "--metadata-load", type=str, help="Load a metadata file created using (-s)")
    group.add_argument("-i", "--metadata-csv-input", type=str, help="Import your own account metadata in CSV format. AWS account numbers must be in column titled 'aws_account_id'")
    parser.add_argument("-r", "--role", type=str, help="Name of an IAM role to assume into member accounts")
    parser.add_argument("-p", "--profile", type=str, help="AWS profile used to get account data from AWS Organizations")
    parser.add_argument("-o", "--csv-output", type=str, help="CSV output filename")
    args = parser.parse_args()

    if args.csv_output and args.metadata_save:
        print("Can't use -o with -s.")
        exit()

    # empty dataframe for final report
    df_final_report = pd.DataFrame()

    # create session using existing profile
    admin_session = boto3.Session()

    # use a profile if we have one
    if args.profile:
        admin_session = boto3.Session(profile_name=args.profile)

    # load our metadata from a file
    if args.metadata_load:
        logging.info("---- Loading account metadata from "+args.metadata_load+" ----")
        f = open(args.metadata_load)
        account_data = json.load(f)
        f.close()

        df_account_data = pd.json_normalize(account_data['Accounts'])

    elif args.metadata_csv_input:
        logging.info("---- Loading custom CSV account metadata from "+args.metadata_csv_input+" ----")
        df_account_data = pd.read_csv(args.metadata_csv_input)
        
        # check if it has a column titled 'aws_account_id'
        if 'aws_account_id' not in df_account_data.columns:
            logger.exception(args.metadata_csv_input+" doesn't contain a column called 'aws_account_id'")
            exit()

        df_account_data.rename(columns={'aws_account_id': 'Id'}, inplace=True)

    else:
        # otherwise enumerate accounts from AWS Organizations
        logging.info("---- Getting account metadata ----")
        account_data = account_metadata.get_account_metadata(admin_session)
        logging.info("---- Finished getting account metadata ----")
        df_account_data = pd.json_normalize(account_data['Accounts'])

    if args.metadata_save:
        # write metadata to disk
        json_object = json.dumps(account_data, indent=4)
        logger.info("---- Writing account metadata to "+args.metadata_save+" file ----")
        with open(args.metadata_save, "w") as outfile:
            outfile.write(json_object)

        exit()

    # create sts client
    sts = admin_session.client("sts")

    # get credential report for each account
    logging.info("---- Attempting to use "+args.role+" role to assume into member accounts ----")
    for account in df_account_data['Id']:
        if (account.isnumeric() and len(account) == 12):
            try:
                response = sts.assume_role(
                        RoleArn="arn:aws:iam::"+account+":role/"+args.role,
                        RoleSessionName="learnaws-test-session"
                        )
                        
                assumed_session = boto3.Session(aws_access_key_id=response['Credentials']['AccessKeyId'],
                        aws_secret_access_key=response['Credentials']['SecretAccessKey'],
                        aws_session_token=response['Credentials']['SessionToken'])
            
                # get list of users in account who have active keys
                df_users = iam_helper.get_active_access_keys(assumed_session)
                
                if df_users.empty:
                    logging.info("["+account+"]: No active access keys")
                else:
                    # assume all users have low privileges until we discover them
                    df_users['HighPrivilege'] = False

                    for username in df_users['user']:

                        policies = []
                        user = {}
                        user['UserName'] = username
                        dangerous_policies = ['Administrator', 'FullAccess', 'PowerUser']
                        
                        output = iam_helper.get_managed_policies(assumed_session, user)
                        for policy in output['ManagedPolicies']:
                            if any([x in policy['Name'] for x in dangerous_policies]):
                                logging.info("["+account+"]: Danger! - "+user['UserName']+" has policy:"+policy['Name'])
                                df_users.loc[df_users.user == user['UserName'], 'HighPrivilege'] = True
                                policies.append(policy['Name'])
                            else:
                                logging.debug("["+account+"]: Not dangerous - "+user['UserName']+" has policy:"+policy['Name'])
                        df_users.loc[df_users.user == user['UserName'], 'policies'] = str(policies)

                    # add account number to make joining easy
                    df_users['AccountNo'] = account
                    df_keys_metadata = pd.merge(df_account_data, df_users, left_on='Id', right_on='AccountNo')
                
                    # append it to the final df
                    df_final_report = pd.concat([df_final_report, df_keys_metadata])
                
            except ClientError as error:
                logger.exception("["+account+"]: Couldn't Assume Role - arn:aws:iam::"+account+":role/"+args.role)
                pass
        else:
            logger.exception("["+account+"]: is not a valid AWS account Id")

    # reset the index and output to csv
    df_final_report = df_final_report.reset_index()
    del df_final_report['index']
    logger.info("---- Writing CSV output to "+args.csv_output+" ----")
    df_final_report.to_csv(args.csv_output, index=False)

if __name__ == '__main__':
    main()