import logging
import argparse
import os
import sys

import boto3


logging.basicConfig(filename='log.txt',
                    level=logging.INFO,
                    format='loglevel: %(levelname)s, time: %(asctime)s, msg: %(message)s')


# ---------------------------- Client Creation ----------------------------


def create_boto_client(region, access_key=None, secret_key=None):
    """Create and return an EC2 client."""
    try:
        return boto3.client(
            'ec2',
            region_name=region,
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key
        )
    except Exception as e:
        logging.error(f'Failed to create boto client: {e}')


def create_s3_client(region, access_key=None, secret_key=None):
    """Create and return an S3 client."""
    try:
        return boto3.client(
            's3',
            region_name=region,
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key
        )
    except Exception as e:
        logging.error(f'Failed to create s3 client: {e}')


# ---------------------------- Security Group/S3/Logging Actions ----------------------------


def get_all_sgs(boto_instance):
    """
    Returns security groups, will be used for security group actions
    :param boto_instance: boto3 client created earlier
    :return: Security groups
    """
    try:
        return boto_instance.describe_security_groups()['SecurityGroups']
    except Exception as e:
        logging.error(f"Error retrieving security groups: {e}")
        return []


def check_inbound_rule(security_group):
    """
    Gets sercurity groups object and checks for each security group if there is a "bad rule"
    :param security_group: create_boto_client()
    :return: boolean & inbound rule if true (for each security group in a VPC), boolean & None if not
    """
    for perm in security_group.get('IpPermissions', []):
        for ip_range in perm.get('IpRanges', []):
            if ip_range.get('CidrIp') == '0.0.0.0/0':
                return True, perm
    return False, None


def log_sg(sg_id, rule):
    """
    Logs and prints log_msg, used inside another function (scan_and_fix_security_groups)
    :param sg_id: check_inbound_rule output
    :param rule: check_inbound_rule output
    """
    log_msg = f'Open access found in SG {sg_id}: {rule}'
    logging.info(log_msg)
    print(log_msg)


def remove_inbound_rule(boto3_client, sg_id, rule):
    """
    Removes specified inbound rule, a single action which is triggered
    in scan_and_fix_security_groups
    :param boto3_client: boto3 client created earlier
    :param sg_id: check_inbound_rule output
    :param rule: check_inbound_rule output
    """
    try:
        boto3_client.revoke_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[rule]
        )
        logging.info(f"Removed inbound rule from SG: {sg_id}")
    except Exception as e:
        logging.error(f"Error removing inbound rule from SG {sg_id}: {e}")


def upload_to_s3(s3_client, bucket_name):
    """
    Uploads the log file (created locally/inside the container) to the specified S3 bucket.
    a log file will be created locally when running the script from your local machine.
    :param s3_client: s3 client created earlier
    :param bucket_name: inserted with args
    :return:
    """
    try:
        s3_client.upload_file('log.txt', bucket_name, 'log.txt')
        logging.info(f"Log file uploaded to S3 bucket: {bucket_name}")
    except Exception as e:
        logging.error(f"Error uploading log file to S3: {e}")


def scan_and_fix_security_groups(boto_client, log_mode):
    """
    Scans all security groups, if a security group has
    a "bad inbound rule" it will be removed and logged,
    :param boto_client: boto client created earlier
    :param log_mode: inserted with args
    """
    bad_inbound_rule = False
    security_groups = get_all_sgs(boto_client)
    for sg in security_groups:
        open_access, rule = check_inbound_rule(sg)
        if open_access:
            log_sg(sg['GroupId'], rule)
            bad_inbound_rule = True
            if not log_mode:
                remove_inbound_rule(boto_client, sg['GroupId'], rule)
    if not bad_inbound_rule:
        log_msg = 'All Security Groups does not allow communication from 0.0.0.0/0'
        logging.info(log_msg)
        print(log_msg)


# ---------------------------- Flow execution ----------------------------


def run_flow():
    try:
        parser = argparse.ArgumentParser(description="Scan and fix open security groups")
        parser.add_argument("--access-key", help="AWS Access Key ID")
        parser.add_argument("--secret-key", help="AWS Secret Access Key")
        parser.add_argument("--region", help="AWS Region", required=True)
        parser.add_argument("--log-mode",
                            help="Run in log mode without making changes"
                                 "(does not delete the inbound rule)",
                            action='store_true')
        parser.add_argument("--bucket", help="S3 Bucket Name for log upload", required=True)
        args = parser.parse_args()
        access_key = args.access_key or os.getenv('AWS_ACCESS_KEY_ID')
        secret_key = args.secret_key or os.getenv('AWS_SECRET_ACCESS_KEY')
        boto_client = create_boto_client(args.region, access_key, secret_key)
        s3_client = create_s3_client(args.region, args.access_key, args.secret_key)
        scan_and_fix_security_groups(boto_client, args.log_mode)
        upload_to_s3(s3_client, args.bucket)

        if boto_client is None or s3_client is None:
            logging.error('Failed to create AWS client, exiting')
            sys.exit(1)
    except Exception as e:
        logging.error(f'An error occurred while script execution: {e}')


if __name__ == "__main__":
    run_flow()
