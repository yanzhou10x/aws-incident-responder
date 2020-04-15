import collections
import requests

AWS_IP_RANGE_URL = 'https://ip-ranges.amazonaws.com/ip-ranges.json'


class AwsUtility:
    @staticmethod
    def get_aws_ip_ranges():
        aws_ip_ranges = collections.defaultdict(list)
        data = requests.get(AWS_IP_RANGE_URL).json()

        for ip in data.get('prefixes'):
            region = ip.get('region')
            ip_cidr = ip.get('ip_prefix')
            aws_ip_ranges[region].append(ip_cidr)

        return aws_ip_ranges

    @staticmethod
    def is_aws_service(request_service):
        aws_suffix = '.amazonaws.com'

        if request_service.endswith(aws_suffix):
            return True
        else:
            return False

