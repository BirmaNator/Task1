import logging
import argparse
import os
import sys
from typing import Optional, Tuple, Dict, Any

import boto3
from botocore.client import BaseClient

logging.basicConfig(filename='log.txt',
                    level=logging.INFO,
                    format='loglevel: %(levelname)s, time: %(asctime)s, msg: %(message)s')


# ---------------------------- Client Creation ----------------------------


def create_boto_client(region: str, access_key: Optional[str] = None,
                       secret_key: Optional[str] = None) -> Optional[BaseClient]:
    """Create and return a boto3 client."""
    try:
        return boto3.client(
            'ec2',
            region_name=region,
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key
        )
    except Exception as e:
        logging.error(f'Failed to create boto client: {e}')


def create_s3_client(region: str, access_key: Optional[str] = None,
                     secret_key: Optional[str] = None) -> Optional[BaseClient]:
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


def _get_all_sgs(boto_instance: BaseClient) -> list:
    """Returns security groups, will be used for security group actions"""
    try:
        return boto_instance.describe_security_groups()['SecurityGroups']
    except Exception as e:
        logging.error(f"Error retrieving security groups: {e}")
        return []


def _check_inbound_rule(security_group: Dict[str, Any]) -> Tuple[bool, Optional[Dict[str, Any]]]:
    """
    Gets sercurity groups object and checks for each security group if there is a "bad rule"
    :param security_group: AWS security group object which contains multiple attributes
    :return: bool (contain a bad rule or not), details of a rule (contains multiple attributes) or None
    """
    for perm in security_group.get('IpPermissions', []):
        for ip_range in perm.get('IpRanges', []):
            if ip_range.get('CidrIp') == '0.0.0.0/0':
                return True, perm
    return False, None


def _log_sg(sg_id: str, rule: Dict[str, Any]) -> None:
    """ Logs and prints log_msg, used inside another function (scan_and_fix_security_groups)"""
    log_msg = f'Open access found in SG {sg_id}: {rule}'
    logging.info(log_msg)
    print(log_msg)


def _remove_inbound_rule(boto3_client: BaseClient, sg_id: str, rule: Dict[str, Any]) -> None:
    """ Removes a specified inbound rule from a security group."""
    try:
        boto3_client.revoke_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[rule]
        )
        logging.info(f"Removed inbound rule from SG: {sg_id}")
    except Exception as e:
        logging.error(f"Error removing inbound rule from SG {sg_id}: {e}")


def upload_to_s3(s3_client: BaseClient, bucket_name: str) -> None:
    """Uploads the log file (created locally/inside the container) to the specified S3 bucket."""
    try:
        s3_client.upload_file('log.txt', bucket_name, 'log.txt')
        logging.info(f"Log file uploaded to S3 bucket: {bucket_name}")
    except Exception as e:
        logging.error(f"Error uploading log file to S3: {e}")


def scan_and_fix_security_groups(boto_client: BaseClient, log_mode: bool) -> None:
    """Scans all security groups, if a security group has a "bad inbound" rule it will be removed and logged"""
    bad_inbound_rule = False
    security_groups = _get_all_sgs(boto_client)
    for sg in security_groups:
        open_access, rule = _check_inbound_rule(sg)
        if open_access:
            _log_sg(sg['GroupId'], rule)
            bad_inbound_rule = True
            if not log_mode:
                _remove_inbound_rule(boto_client, sg['GroupId'], rule)
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
