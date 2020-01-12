import os
import boto3
import json
from botocore.vendored import requests
from ipaddress import ip_network, ip_address


def get_cloudflare_ip_list():
    """ Call the CloudFlare API and return a list of IPs """
    response = requests.get('https://api.cloudflare.com/client/v4/ips')
    temp = response.json()
    if 'result' in temp:
        ipv4_list = temp['result']['ipv4_cidrs']
        new_ipv4s = []
        for ip in ipv4_list:
            mask = int(ip.split(u'/')[1])
            if (mask == 8 or (mask >= 16 and mask <= 32)):
                new_ipv4s.append(ip)
                continue
            for new_ip in ip_network(ip).subnets(new_prefix=16):
                new_ipv4s.append(str(new_ip))
        temp['result']['ipv4_cidrs_workaround'] = new_ipv4s

        ipv6_list = temp['result']['ipv6_cidrs']
        new_ipv6s = []
        for ip in ipv6_list:
            mask = int(ip.split(u'/')[1])
            if (mask in [24, 32, 48, 56, 64, 128]):
                new_ipv6s.append(ip)
                continue
            new_prefix = 32
            for supported_mask in [24, 32, 48, 56, 64, 128]:
                if mask <= supported_mask:
                    new_prefix = supported_mask
                    break
            for new_ip in ip_network(ip).subnets( new_prefix = new_prefix ):
                new_ipv6s.append(str(new_ip))
        temp['result']['ipv6_cidrs_workaround'] = new_ipv6s

        return temp['result']
    raise Exception("Cloudflare response error")


def get_aws_s3_bucket_policy(s3_id):
    """ Return the Policy of an S3 """
    s3 = boto3.client('s3')
    result = s3.get_bucket_policy(Bucket=s3_id)
    if not 'Policy' in result:
        raise Exception("Failed to retrieve Policy from S3 %s" % (s3_id))
    policy = json.loads(result['Policy'])
    return { 'id' : s3_id, s3_id : policy }


def check_waf_v1_ipset_ipvx_rule_exists(ipset_content, address, ip_type):
    """ Check if the rule currently exists """
    if not "IPSet" in ipset_content:
        raise Exception("Structure of IP SET v1 is not well formated. Missing 'IPSet' tag.")

    ipset = ipset_content['IPSet']

    if not "IPSetDescriptors" in ipset:
        raise Exception("Structure of IP SET v1 is not well formated. Missing 'IPSetDescriptors' tag inside 'IPSet'.")
    ipset_descriptors = ipset['IPSetDescriptors']

    for ipset_descriptor in ipset_descriptors:
        if not ip_type == ipset_descriptor['Type']:
            continue
        print("Address '%s'" % (address))
        print("Value '%s'" % (ipset_descriptor['Value']))
        print("Type '%s'" % (ipset_descriptor['Type']))

        net_ipaddr = ip_network(address)
        net_value = ip_network(ipset_descriptor['Value'])
        if net_ipaddr == net_value or net_ipaddr.overlaps(net_value):
            return True
    return False

def add_waf_v1_ipset_ipvx_rule(ipset_id, ip_address, ip_type):
    """ Add the IP address to an IP Set from AWS WAF v1 """
    waf = boto3.client('waf')
    change_token_response = waf.get_change_token()
    change_token = change_token_response['ChangeToken']

    updates = [{
            'Action': 'INSERT',
            'IPSetDescriptor': {
                'Type': ip_type,
                'Value': ip_address
            }
        }]

    waf.update_ip_set(
        IPSetId = ipset_id,
        ChangeToken = change_token,
        Updates = updates
    )

    print("Added %s (%s) to %s  " % (ip_address, ip_type, ipset_id))
    return


def delete_waf_v1_ipset_ipvx_rule(ipset_id, ip_address, ip_type):
    """ Delete the IP address of an IP Set from AWS WAF v1 """
    waf = boto3.client('waf')
    change_token_response = waf.get_change_token()
    change_token = change_token_response['ChangeToken']

    updates = [{
            'Action': 'DELETE',
            'IPSetDescriptor': {
                'Type': ip_type,
                'Value': ip_address
            }
        }]
    waf.update_ip_set(
        IPSetId = ipset_id,
        ChangeToken = change_token,
        Updates = updates
    )

    print("Deleted %s (%s) to %s  " % (ip_address, ip_type, ipset_id))
    return


def get_waf_v1_ipset(ipset_id):
    """ Return the defined IP Set from AWS WAF v1 """
    waf = boto3.client('waf')
    policy =  waf.get_ip_set( IPSetId = ipset_id )
    #policy =  json.loads(waf.get_ip_set( IPSetId = ipset_id ))
    return { 'id' : ipset_id, 'content' : policy }


def check_waf_v1_ipset_ipv4_rule_exists(ipset_content, address):
    """ Check if the rule currently exists """
    return check_waf_v1_ipset_ipvx_rule_exists(ipset_content, address, 'IPV4')


def add_waf_v1_ipset_ipv4_rule(ipset_id, ip_address):
    """ Add the IPv4 address to the IP Set from AWS WAF v1 """
    add_waf_v1_ipset_ipvx_rule(ipset_id, ip_address, 'IPV4')


def delete_waf_v1_ipset_ipv4_rule(ipset_id, ip_address):
    """ Delete the IP address of an IP Set from AWS WAF v1 """
    delete_waf_v1_ipset_ipvx_rule(ipset_id, ip_address, 'IPV4')


def check_waf_v1_ipset_ipv6_rule_exists(ipset_content, address):
    """ Check if the rule currently exists """
    return check_waf_v1_ipset_ipvx_rule_exists(ipset_content, address, 'IPV6')


def add_waf_v1_ipset_ipv6_rule(ipset_id, ip_address):
    """ Add the IPv6 address to the IP Set from AWS WAF v1 """
    add_waf_v1_ipset_ipvx_rule(ipset_id, ip_address, 'IPV6')


def delete_waf_v1_ipset_ipv6_rule(ipset_id, ip_address):
    """ Delete the IP address of an IP Set from AWS WAF v1 """
    delete_waf_v1_ipset_ipvx_rule(ipset_id, ip_address, 'IPV6')


def get_aws_security_group(group_id):
    """ Return the defined Security Group """
    ec2 = boto3.resource('ec2')
    group = ec2.SecurityGroup(group_id)
    if group.group_id == group_id:
        return group
    raise Exception('Failed to retrieve Security Group')


def check_ipv4_rule_exists(rules, address, port):
    """ Check if the rule currently exists """
    for rule in rules:
        for ip_range in rule['IpRanges']:
            if ip_range['CidrIp'] == address and rule['FromPort'] == port:
                return True
    return False


def add_ipv4_rule(group, address, port):
    """ Add the IP address/port to the security group """
    group.authorize_ingress(IpProtocol="tcp",
                            CidrIp=address,
                            FromPort=port,
                            ToPort=port)
    print("Added %s : %i to %s  " % (address, port, group.group_id))


def delete_ipv4_rule(group, address, port):
    """ Remove the IP address/port from the security group """
    group.revoke_ingress(IpProtocol="tcp",
                         CidrIp=address,
                         FromPort=port,
                         ToPort=port)
    print("Removed %s : %i from %s  " % (address, port, group.group_id))


def check_ipv6_rule_exists(rules, address, port):
    """ Check if the rule currently exists """
    for rule in rules:
        for ip_range in rule['Ipv6Ranges']:
            if ip_range['CidrIpv6'] == address and rule['FromPort'] == port:
                return True
    return False


def add_ipv6_rule(group, address, port):
    """ Add the IP address/port to the security group """
    group.authorize_ingress(IpPermissions=[{
        'IpProtocol': "tcp",
        'FromPort': port,
        'ToPort': port,
        'Ipv6Ranges': [
            {
                'CidrIpv6': address
            },
        ]
    }])
    print("Added %s : %i to %s  " % (address, port, group.group_id))


def delete_ipv6_rule(group, address, port):
    """ Remove the IP address/port from the security group """
    group.revoke_ingress(IpPermissions=[{
        'IpProtocol': "tcp",
        'FromPort': port,
        'ToPort': port,
        'Ipv6Ranges': [
            {
                'CidrIpv6': address
            },
        ]
    }])
    print("Removed %s : %i from %s  " % (address, port, group.group_id))


def update_ip_set_v1_policies(ip_addresses):
    """ Updates IP set from AWS WAF Classic """
    if not "IPSET_V1_IDS_LIST" in os.environ and not "IPSET_V1_ID" in os.environ:
        print("Missing Web ACL Classic configuration 'IPSET_V1_IDS_LIST' or 'IPSET_V1_ID'. Will not check Security Policy.") 
        return
   
    ip_sets = map(get_waf_v1_ipset, os.environ['IPSET_V1_IDS_LIST'].split(","))
    if not ip_sets:
        ip_sets = [get_waf_v1_ipset(os.environ['IPSET_V1_ID'])]
    
    ## Security Groups
    for ipset in ip_sets: 
        ipset_id = ipset['id']
        current_rules = ipset['content']
        ## IPv4
        # add new addresses
        for ipv4_cidr in ip_addresses['ipv4_cidrs_workaround']:
            if not check_waf_v1_ipset_ipv4_rule_exists(current_rules, ipv4_cidr):
                add_waf_v1_ipset_ipv4_rule(ipset_id, ipv4_cidr)

        ## IPv6 -- because of boto3 syntax, this has to be separate
        # add new addresses
        for ipv6_cidr in ip_addresses['ipv6_cidrs_workaround']:
            if not check_waf_v1_ipset_ipv6_rule_exists(current_rules, ipv6_cidr):
                add_waf_v1_ipset_ipv6_rule(ipset_id, ipv6_cidr)

        # remove old addresses
        for rule in current_rules['IPSet']['IPSetDescriptors']:
            ip_type = rule['Type']
            ip_addr = rule['Value']

            in_ipv4 = False
            in_ipv6 = False
            if 'IPV4' == ip_type:
                for addr in ip_addresses['ipv4_cidrs_workaround']:
                    if ip_address(ip_addr) in ip_network(ip_addr):
                        in_ipv4 = True
                        break
            if 'IPV6' == ip_type:
                for addr in ip_addresses['ipv6_cidrs_workaround']:
                    if ip_address(ip_addr) in ip_network(ip_addr):
                        in_ipv4 = True
                        break

            in_ipv4 = ip_addr in ip_addresses['ipv4_cidrs_workaround']
            in_ipv6 = ip_addr in ip_addresses['ipv6_cidrs_workaround']

            if not in_ipv6 and not in_ipv4:
                delete_waf_v1_ipset_ipvx_rule(ipset_id, ip_addr, ip_type)

    return


def update_s3_policies(ip_addresses):
    """ Update S3 policies """
    print("Checking policies of S3")

    s3 = boto3.client('s3')

    ipv4 = ip_addresses['ipv4_cidrs']
    ipv6 = ip_addresses['ipv6_cidrs']

    cloudflare_ips = ipv4 + ipv6

    if not "S3_CLOUDFLARE_SID" in os.environ:
        print("Not configured 'S3_CLOUDFLARE_SID' variable, so will not check S3")
        return

    if not "S3_BUCKET_IDS_LIST" in os.environ and not "S3_BUCKET_ID" in os.environ:
        raise Exception("Missing S3 basic configuration 'S3_BUCKET_IDS_LIST' or 'S3_BUCKET_ID'.") 

    sid = os.environ['S3_CLOUDFLARE_SID']
    s3_policy_tuple = map(get_aws_s3_bucket_policy, os.environ['S3_BUCKET_IDS_LIST'].split(","))
    if not s3_policy_tuple:
        s3_policy_tuple = [get_aws_s3_bucket_policy(os.environ['S3_BUCKET_ID'])]

    for s3_tuple in s3_policy_tuple:
        updated = False
        s3_id = s3_tuple['id']
        print("Checking Policy of S3 Bucket '%s'" % (s3_id) )
        policy = s3_tuple[s3_id]
        if not 'Statement' in policy:
            raise Exception("Problem reading policy of S3 Bucket '%s'" % (s3_id) )
        for statement in policy['Statement']:
            if not "Sid" in statement:
                raise Exception("Problem reading Sid inside Statement of S3 Bucket '%s'" % (s3_id) )
            if ((not sid == statement['Sid']) or
              (not "Condition" in statement) or
              (not "IpAddress" in statement["Condition"]) or
              (not "aws:SourceIp" in statement["Condition"]["IpAddress"])):
                continue

            statement["Condition"]["IpAddress"]["aws:SourceIp"] = cloudflare_ips
            updated = True

        if updated:
            policy = json.dumps(policy)
            print("Going to update policy %s " % (s3_id) )
            s3.put_bucket_policy(Bucket=s3_id, Policy=policy)


def update_security_group_policies(ip_addresses):
    """ Update Information of Security Groups """
    print("Checking policies of Security Groups")

    if not "SECURITY_GROUP_IDS_LIST" in os.environ and not "SECURITY_GROUP_ID" in os.environ:
        print("Missing S3 basic configuration 'SECURITY_GROUP_IDS_LIST' or 'SECURITY_GROUP_ID'. Will not check Security Policy.") 
        return
   
    ports = map(int, os.environ['PORTS_LIST'].split(","))
    if not ports:
        ports = [80]

    security_groups = map(get_aws_security_group, os.environ['SECURITY_GROUP_IDS_LIST'].split(","))
    if not security_groups:
        security_groups = [get_aws_security_group(os.environ['SECURITY_GROUP_ID'])]
    
    ## Security Groups
    for security_group in security_groups: 
        current_rules = security_group.ip_permissions
        ## IPv4
        # add new addresses
        for ipv4_cidr in ip_addresses['ipv4_cidrs']:
            for port in ports:
                if not check_ipv4_rule_exists(current_rules, ipv4_cidr, port):
                    add_ipv4_rule(security_group, ipv4_cidr, port)
    
        # remove old addresses
        for port in ports:
            for rule in current_rules:
                # is it necessary/correct to check both From and To?
                if rule['FromPort'] == port and rule['ToPort'] == port:
                    for ip_range in rule['IpRanges']:
                        if ip_range['CidrIp'] not in ip_addresses['ipv4_cidrs']:
                            delete_ipv4_rule(security_group, ip_range['CidrIp'], port)
    
        ## IPv6 -- because of boto3 syntax, this has to be separate
        # add new addresses
        for ipv6_cidr in ip_addresses['ipv6_cidrs']:
            for port in ports:
                if not check_ipv6_rule_exists(current_rules, ipv6_cidr, port):
                    add_ipv6_rule(security_group, ipv6_cidr, port)
    
        # remove old addresses
        for port in ports:
            for rule in current_rules:
                for ip_range in rule['Ipv6Ranges']:
                    if ip_range['CidrIpv6'] not in ip_addresses['ipv6_cidrs']: 
                        delete_ipv6_rule(security_group, ip_range['CidrIpv6'], port)


def lambda_handler(event, context):
    """ AWS Lambda main function """
    
    ip_addresses = get_cloudflare_ip_list()

    update_ip_set_v1_policies(ip_addresses)

    update_security_group_policies(ip_addresses)

    update_s3_policies(ip_addresses)
