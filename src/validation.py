import ast
from netaddr import IPAddress, IPNetwork


def check_ip_network(ip, network):
    if ip == 'all':
        return False
    if IPAddress(ip) in IPNetwork(network):
        return True
    else:
        return False


def check_rule(dict_intent):
    if dict_intent['intent_type'] == 'acl':
        file = 'src/log/acl_log'
    elif dict_intent['intent_type'] == 'nat11':
        file = 'src/log/nat_log'
    elif dict_intent['intent_type'] == 'traffic_shaping':
        file = 'src/log/ts_log'
    # check name
    if dict_intent['intent_type'] == 'acl' or dict_intent['intent_type'] == 'traffic_shaping':
        ctr = 0
        with open(file) as archive:
            for line in archive:
                if '#' not in line[0:5] and line[0:1] != "\n":
                    dict_rule = ast.literal_eval(line)
                    if dict_rule['name'] == dict_intent['name']:
                        ctr = 1
                        if dict_intent['apply'] == 'insert':
                            return 'ERROR NAME: Rule named "' + dict_intent[
                                'name'] + '" already exists in devices ' + str(dict_rule['devices'])
            if ctr == 0 and dict_intent['apply'] == 'remove':
                return 'ERROR NAME: Rule named "' + dict_intent['name'] + '" not found'
    # check duplicate
    with open(file) as archive:
        for line in archive:
            if '#' not in line[0:5] and line[0:1] != "\n":
                dict_rule = ast.literal_eval(line)
                if dict_intent['apply'] == 'insert':
                    if dict_intent['from'] == dict_rule['from']:
                        if dict_intent['to'] == dict_rule['to']:
                            if dict_intent['intent_type'] == 'nat11':
                                if dict_intent['protocol'] == dict_rule['protocol']:
                                    return 'ERROR DUPLICATE: This NAT intention already exist'
                            elif dict_intent['intent_type'] == 'acl':
                                if dict_intent['traffic'] == dict_rule['traffic']:
                                    if dict_intent['rule'] == dict_rule['rule']:
                                        return 'ERROR DUPLICATE: The ACL rule "' + dict_rule[
                                            'name'] + '" already treats this intention'
                                    else:
                                        if dict_intent['rule'] == 'allow':
                                            return 'ERROR DUPLICATE: The ACL rule "' + dict_rule[
                                                'name'] + '" blocks this intention'
                                        else:
                                            return 'ERROR DUPLICATE: The ACL rule "' + dict_rule[
                                                'name'] + '" allowed this intention'
                            elif dict_intent['intent_type'] == 'traffic_shaping':
                                if dict_intent['traffic'] == dict_rule['traffic']:
                                    return 'ERROR DUPLICATE: The rule "' + dict_rule[
                                        'name'] + '" already treats this intention'
    # check ranges networks
    if dict_intent['intent_type'] == 'acl' or dict_intent['intent_type'] == 'traffic_shaping':
        with open(file) as archive:
            for line in archive:
                if '#' not in line[0:5] and line[0:1] != "\n":
                    dict_rule = ast.literal_eval(line)
                    if dict_intent['apply'] == 'insert':
                        if 'from_mask' in dict_rule and 'from_mask' not in dict_intent:
                            if check_ip_network(dict_intent['from'], dict_rule['from'] + '/' + str(IPAddress(dict_rule['from_mask']).netmask_bits())):
                                if dict_intent['to'] == dict_rule['to']:
                                    if dict_intent['traffic'] == dict_rule['traffic']:
                                        if dict_intent['intent_type'] == 'acl':
                                            if dict_intent['rule'] == dict_rule['rule']:
                                                return 'ERROR DUPLICATE: The rule "' + dict_rule[
                                                    'name'] + '" already treats this intention'
                                        elif dict_intent['intent_type'] == 'traffic_shaping':
                                            return 'ERROR DUPLICATE: The rule "' + dict_rule[
                                                'name'] + '" already treats this intention'
                        if 'to_mask' in dict_rule and 'to_mask' not in dict_intent:
                            if check_ip_network(dict_intent['to'], dict_rule['to'] + '/' + str(
                                    IPAddress(dict_rule['to_mask']).netmask_bits())):
                                if dict_intent['from'] == dict_rule['from']:
                                    if dict_intent['traffic'] == dict_rule['traffic']:
                                        if dict_intent['intent_type'] == 'acl':
                                            if dict_intent['rule'] == dict_rule['rule']:
                                                return 'ERROR DUPLICATE: The rule "' + dict_rule[
                                                    'name'] + '" already treats this intention'
                                        elif dict_intent['intent_type'] == 'traffic_shaping':
                                            return 'ERROR DUPLICATE: The rule "' + dict_rule[
                                                'name'] + '" already treats this intention'
    archive.close()
    archive = open(file)
    lines = archive.readlines()
    if dict_intent['apply'] == 'insert':
        lines.append(str(dict_intent) + '\n')
    else:
        ctr = 0
        for line_num, l in enumerate(lines, 0):
            if '#' not in l[0:5] and l[0:1] != "\n":
                ctr = 1
                dict_rule = ast.literal_eval(l)
                if dict_intent['intent_type'] == 'acl' or dict_intent['intent_type'] == 'traffic_shaping':
                    if dict_intent['name'] == dict_rule['name']:
                        line = line_num
                else:
                    if dict_intent['from'] == dict_rule['from'] and dict_intent['to'] == dict_rule['to'] and \
                            dict_intent['protocol'] == dict_rule['protocol']:
                        line = line_num
        if ctr == 0:
            return 'ERROR: This NAT intention does not exist'
        lines.pop(line)
    archive.close()
    archive = open(file, 'w')
    archive.writelines(lines)
    archive.close()
    return 'OK'


def remove_error_rule(dict_intent):
    if dict_intent['intent_type'] == 'acl':
        file = 'src/log/acl_log'
    elif dict_intent['intent_type'] == 'nat11':
        file = 'src/log/nat_log'
    elif dict_intent['intent_type'] == 'traffic_shaping':
        file = 'src/log/ts_log'
    archive = open(file)
    lines = archive.readlines()
    ctr = 0
    for line_num, l in enumerate(lines, 0):
        if '#' not in l[0:5] and l[0:1] != "\n":
            ctr = 1
            dict_rule = ast.literal_eval(l)
            if dict_intent['intent_type'] == 'acl' or dict_intent['intent_type'] == 'traffic_shaping':
                if dict_intent['name'] == dict_rule['name']:
                    line = line_num
            else:
                if dict_intent['from'] == dict_rule['from'] and dict_intent['to'] == dict_rule['to'] and \
                        dict_intent['protocol'] == dict_rule['protocol']:
                    line = line_num
    if ctr == 0:
        return 'ERROR: This NAT intention does not exist'
    lines.pop(line)
    archive.close()
    archive = open(file, 'w')
    archive.writelines(lines)
    archive.close()
