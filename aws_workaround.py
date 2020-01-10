from ipaddress import ip_address, ip_network

def aws_workaround_convert_to_smaller_cidr(network_address, target_mask = 16):
    """ 
        That is a workaround function to convert larger masks into a list
        of smaller networks.
        It was created due a AWS restriction that just support those networks
        /8 or any range from /16 to /32.
    """
    result_networks = []
    net_in_convertion = ip_network(network_address, strict=False)
    net_size = ((int(net_in_convertion[-1]) - int(net_in_convertion[0])))
    x = 0
    while x < net_size:
        ip = net_in_convertion[x]
        ip_in_netrange = False
        for net in result_networks:
            if ip_address(ip) in ip_network(net):
                ip_in_netrange = True
                break
        if ip_in_netrange:
            x += 1
            continue
        ip_with_mask = ip_network(u"%s/%s" % (ip, target_mask), strict=False)
        result_networks.append(ip_with_mask)
        jump_size = (int(ip_with_mask[-1]) - int(ip)) - 1
        x += jump_size
    return result_networks
