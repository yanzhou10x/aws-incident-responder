import ipaddress
import os
import boto3
import pandas as pd
from aws_util import AwsUtility

SECURITY_PROFILE = 'security'
TARGET_PROFILE = 'target_security'
LOG_BUCKET_NAME = 'flaws2-logs'


class Defender:
    def __init__(self, security_profile, target_profile, log_s3_bucket):
        self.security_session = boto3.session.Session(profile_name=security_profile)
        self.target_session = boto3.session.Session(profile_name=target_profile)
        self.log_s3_bucket = log_s3_bucket

        self.aws_ip_ranges = AwsUtility.get_aws_ip_ranges()
        self.target_roles_df = self.retrieve_target_roles()

        self.verified_aws_ip = set()
        self.verified_non_aws_ip = set()

        self.download_logs()

    def detect_attacks(self):
        """
        detect attacks by joining cloudtrail log entries with iam roles in target account on ARN

        if source ip is not within AWS IP range, alert the incident
        """
        events_df = self.read_events_to_dataframe()
        events_df = events_df.merge(self.target_roles_df, on='Arn')

        for index, row in events_df.iterrows():
            role_policy = row.get('AssumeRolePolicyDocument')
            if not role_policy:
                continue

            request_service = role_policy['Statement'][0]['Principal']['Service']
            source_ip = row.get('SourceIpAddr')
            arn = row.get('Arn')
            region = row.get('AwsRegion')

            if AwsUtility.is_aws_service(request_service) and (not self.is_aws_ip(source_ip, region)):
                event_time = row.get('EventTime')

                print(f'=============== Attack Detected !!! ================\n'
                      f'EventTime:\t {event_time}\n'
                      f'SourceIP:\t {source_ip}\n'
                      f'AWS Region:\t {region}\n'
                      f'Service:\t {request_service}\n'
                      f'IAM Role:\t {arn}\n')

    def download_logs(self) -> None:
        s3 = self.security_session.resource('s3')
        log_bucket = s3.Bucket(self.log_s3_bucket)

        if not os.path.exists(self.log_s3_bucket):
            os.mkdir(self.log_s3_bucket)

        for obj in log_bucket.objects.all():
            path, filename = os.path.split(obj.key)
            log_bucket.download_file(obj.key, f'./{self.log_s3_bucket}/{filename}')

        gunzip_cmd = 'find . -type f -exec gunzip -q {} \;'
        os.system(gunzip_cmd)

    def retrieve_target_roles(self):
        iam_resource = self.target_session.client('iam')

        roles = iam_resource.list_roles()['Roles']
        roles_df = pd.DataFrame(roles)
        return roles_df

    def read_events_to_dataframe(self):
        log_csv = 'events.csv'
        jq_cmd = f"cat ./{self.log_s3_bucket}/*.json | jq -cr '.Records[]|[.eventTime, .sourceIPAddress, .awsRegion, " \
                 f".userIdentity.arn, .userIdentity.accountId, .userIdentity.type, " \
                 f".userIdentity.sessionContext.sessionIssuer.arn, .eventName]|@tsv' | sort > {log_csv}"
        os.system(jq_cmd)

        column_names = ["EventTime", "SourceIpAddr", "AwsRegion", "UserArn", "AccountId", "UserIdentityType", "Arn",
                        "EventName"]

        return pd.read_csv(log_csv, names=column_names, sep='\t')

    def is_aws_ip(self, ip_addr, region):
        """

        :param ip_addr: ip address to verify
        :param region: aws region
        :return: True if ip_addr is within aws ip range, False otherwise
        """
        if ip_addr in self.verified_aws_ip:
            return True

        if ip_addr in self.verified_non_aws_ip:
            return False

        for aws_ip_cidr in self.aws_ip_ranges[region]:
            if ipaddress.ip_address(ip_addr) in ipaddress.ip_network(aws_ip_cidr):
                self.verified_aws_ip.add(ip_addr)
                return True

        self.verified_non_aws_ip.add(ip_addr)
        return False


if __name__ == "__main__":
    defender = Defender(SECURITY_PROFILE, TARGET_PROFILE, LOG_BUCKET_NAME)
    defender.detect_attacks()
