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
    group.add_argument("-m", "--metadata-output", type=str, help="Output account metadata to this file and do nothing else")
    group.add_argument("-i", "--metadata-input", type=str, help="Load a metadata file created using (-m)")
    parser.add_argument("-r", "--role", type=str, help="Name of an IAM role to assume into member accounts")
    parser.add_argument("-p", "--profile", type=str, help="AWS profile used to get account data from AWS Organizations")
    parser.add_argument("csv_output", type=str, help="CSV output filename")
    args = parser.parse_args()

    # empty dataframe for final report
    df_final_report = pd.DataFrame()

    # create session using existing profile
    admin_session = boto3.Session()

    # but if we have a profile let's use that
    if args.profile:
        admin_session = boto3.Session(profile_name=args.profile)

    # load out metadata from a file
    if args.metadata_input:
        logging.info("---- Loading account metadata from "+args.metadata_input+" ----")
        f = open(args.metadata_input)
        account_data = json.load(f)
    else:
        # otherwise enumerate accounts from AWS Organizations
        logging.info("---- Getting account metadata ----")
        account_data = account_metadata.get_account_metadata(admin_session)
        logging.info("---- Finished getting account metadata ----")

    if args.metadata_output:
        # Serializing json
        json_object = json.dumps(account_data, indent=4)
 
        # Write metadata to disk
        logger.info("---- Writing account metadata to "+args.metadata_output+" file ----")
        with open(args.metadata_output, "w") as outfile:
            outfile.write(json_object)

        exit()

    df_account_data = pd.json_normalize(account_data['Accounts'])

    # create sts client
    sts = admin_session.client("sts")

    # get credential report for each account
    logging.info("---- Attempting to use "+args.role+" role to assume into member accounts ----")
    for account in df_account_data['Id']:
        
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

    # reset the index and output to csv
    df_final_report = df_final_report.reset_index()
    del df_final_report['index']
    logger.info("---- Writing CSV output to "+args.csv_output+" ----")
    df_final_report.to_csv(args.csv_output, index=False)

if __name__ == '__main__':
    main()