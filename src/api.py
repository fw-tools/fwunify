from flask import Flask, request
import re
import os
import socket
import struct
import datetime
from nameko.standalone.rpc import ClusterRpcProxy
from flask_httpauth import HTTPBasicAuth
from python_json_config import ConfigBuilder
from passlib.hash import pbkdf2_sha256
from PyFwConflict import check_rule, remove_error_rule

auth = HTTPBasicAuth()

builder = ConfigBuilder()
apiProfile = builder.parse_config('etc/users.json')

CONFIG = {'AMQP_URI': "amqp://guest:guest@localhost:5672"}
intent_archive = "intent.txt"
app = Flask(__name__)


def cidr_to_netmask(cidr):
    network, net_bits = cidr.split('/')
    hots_bits = 32 - int(net_bits)
    netmask = socket.inet_ntoa(struct.pack('!I', (1 << 32) - (1 << hots_bits)))
    return network, netmask


def get_line(word):
    with open(intent_archive) as archive:
        for line_num, l in enumerate(archive, 0):
            if word in l:
                return line_num
        return False


def is_valid_ip(ip):
    m = re.match(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$", ip)
    return bool(m) and all(map(lambda n: 0 <= int(n) <= 255, m.groups()))


def is_valid_date_hour(type, value):
    if type == 'hour':
        regex = "^([01]?[0-9]|2[0-3]):[0-5][0-9]$"
        p = re.compile(regex)
        if value == "":
            return False
        if re.search(p, value) is None:
            return False;
        else:
            return True;
    elif type == 'date':
        d, m, y = value.split('/')
        try:
            datetime.datetime(int(y),int(m),int(d))
            return True
        except ValueError:
            return False


def search_in_arq(value, path):
    for line in open(path):
        if '#' not in line[0:2] and line[0:1] != "\n":
            if value in line:
                try:
                    result1, result2, _ = line.split(None, 2)
                except ValueError:
                    result1, result2 = line.split()
                if value == result1 or value == result2:
                    return result1, result2
    return False, False


def identify_value(tag, value):
    tag_status_ok = False
    if tag == 'from' or tag == 'to':
        if is_valid_ip(value):
            tag_status_ok = True
        if value == 'any':
            value = 'all'
            tag_status_ok = True
        if not tag_status_ok:
            result, _ = search_in_arq(value, '/etc/hosts')
            if result is not False:
                if is_valid_ip(result):
                    value = result
                    tag_status_ok = True
        if not tag_status_ok:
            try:
                result = socket.gethostbyname(value)
            except Exception as e:
                return False
            if is_valid_ip(result):
                value = result
                tag_status_ok = True

    elif tag == 'allow' or tag == 'block' or tag == 'for':
        if not tag_status_ok:
            if value == "any":
                tag_status_ok = True
            elif "tcp/" in value or "udp/" in value:
                _, port = value.split('/')
                if port.isdigit():
                    if 0 < int(port) <= 65536:
                        tag_status_ok = True
                    else:
                        return False
                else:
                    return False
        if not tag_status_ok:
            _, value = search_in_arq(value, '/etc/services')
            if value is not False:
                port, proto = value.split('/')
                if port.isdigit():
                    if 0 < int(port) <= 65536:
                        tag_status_ok = True
                        value = proto + '/' + port
                    else:
                        return False
                else:
                    return False
    if tag_status_ok:
        return value
    else:
        return False


def check_parameters(requires, intent):
    flag = 0
    required = []
    for parameter in requires:
        if parameter not in intent:
            required.append(parameter)
    if 'add' in required and 'del' in intent:
        required.remove('add')
    elif 'del' in required and 'add' in intent:
        required.remove('del')
    if 'allow' in required and 'block' in intent:
        required.remove('allow')
    elif 'block' in required and 'allow' in intent:
        required.remove('block')
    if len(required) == 0:
        return True
    else:
        return required


def process_intent_acl(dict_intent, intent_type):
    requires = ['name', 'from', 'to', 'allow', 'block', 'order', 'add', 'del']
    indices = list(dict_intent.keys())
    required = check_parameters(requires, indices)
    if required is not True:
        return "ERROR: The following parameters are mandatory: " + str(required)
    for parameter in indices:
        # parameter name
        if parameter == 'name':
            if "text('" in dict_intent[parameter] and "')" in dict_intent[parameter]:
                dict_intent[parameter] = re.search(r"'(.*)'", dict_intent[parameter]).group(1)
            else:
                return 'Syntax error in parameter: "' + parameter + '".'
        # parameters from and to
        elif parameter == 'from' or parameter == 'to':
            if "endpoint('" in dict_intent[parameter] and "')" in dict_intent[parameter]:
                value = re.search(r"'(.*)'", dict_intent[parameter]).group(1)
                dict_intent[parameter] = value
                result = identify_value(parameter, dict_intent[parameter])
                if not result:
                    return 'Not possible translate parameter "' + parameter + ': ' + dict_intent[parameter] + '"'
                else:
                    dict_intent[parameter] = result
            elif "range('" in dict_intent[parameter] and "')" in dict_intent[parameter]:
                value = re.search(r"'(.*)'", dict_intent[parameter]).group(1)
                range, netmask = cidr_to_netmask(value)
                dict_intent[parameter] = range
                dict_intent[parameter+'_mask'] = netmask
            elif "any" in dict_intent[parameter]:
                dict_intent[parameter] = 'all'
                print('aaaaaa')
            else:
                print(dict_intent[parameter])
                return 'Syntax error in parameter: '+parameter
        # parameters allow e block
        elif parameter == 'allow' or parameter == 'block':
            if "traffic('" in dict_intent[parameter] and "')" in dict_intent[parameter]:
                value = re.search(r"'(.*)'", dict_intent[parameter]).group(1)
                if value == 'any':
                    dict_intent['traffic'] = 'all'
                elif value == 'icmp':
                    dict_intent['traffic'] = 'icmp'
                else:
                    result = identify_value(parameter, value)
                    if result is False:
                        return 'Error in parameter ' + parameter.upper() + ': "' + value + '"'
                    else:
                        dict_intent['traffic'] = result
            else:
                return 'Syntax error in parameter: "' + parameter + '".'
            if parameter == 'allow':
                dict_intent['rule'] = 'allow'
                dict_intent.pop('allow')
            else:
                dict_intent['rule'] = 'block'
                dict_intent.pop('block')
        # parameter order
        elif parameter == 'order':
            if "before('" in dict_intent[parameter] and "')" in dict_intent[parameter]:
                dict_intent['before'] = re.search(r"'(.*)'", dict_intent[parameter]).group(1)
            elif "after('" in dict_intent[parameter] and "')" in dict_intent[parameter]:
                dict_intent['after'] = re.search(r"'(.*)'", dict_intent[parameter]).group(1)
            else:
                return 'Syntax error in parameter: "' + parameter + '".'
            dict_intent.pop('order')
        # parameter logging
        elif parameter == 'logging':
            if 'enable' not in dict_intent[parameter] and 'disable' not in dict_intent[parameter]:
                return 'Syntax error in parameter: "' + parameter + '".'
        # parameters add and del
        elif parameter == 'add' or parameter == 'del':
            if 'firewall' in dict_intent[parameter] or 'middlebox' in dict_intent[parameter]:
                if ',' in dict_intent[parameter]:
                    list_firewall = re.search(r"'(.*)'", dict_intent[parameter]).group(1)
                    list_firewall = list_firewall.replace("'", "")
                    dict_intent['devices'] = list_firewall.split(',')
                    if parameter == 'add':
                        dict_intent['apply'] = 'insert'
                        dict_intent.pop('add')
                    else:
                        dict_intent['apply'] = 'remove'
                        dict_intent.pop('del')
                else:
                    value = []
                    value.append(re.search(r"'(.*)'", dict_intent[parameter]).group(1))
                    dict_intent['devices'] = value
                    if parameter == 'add':
                        dict_intent['apply'] = 'insert'
                        dict_intent.pop('add')
                    else:
                        dict_intent['apply'] = 'remove'
                        dict_intent.pop('del')
            else:
                return 'Error in parameter ' + parameter.upper() + '.'
        # parameter description
        elif parameter == 'description':
            if "text('" in dict_intent[parameter] and "')" in dict_intent[parameter]:
                dict_intent[parameter] = re.search(r"'(.*)'", dict_intent[parameter]).group(1)
            else:
                return 'Syntax error in parameter: "' + parameter + '".'
        # parameters start and end
        elif parameter == 'start':
            if parameter == 'start' and 'end' in indices:
                if "hour('" in dict_intent[parameter] and "')" in dict_intent[parameter] and "hour('" in dict_intent['end'] and "')" in dict_intent['end']:
                    start = re.search(r"'(.*)'", dict_intent[parameter]).group(1)
                    end = re.search(r"'(.*)'", dict_intent['end']).group(1)
                    if re.search(r'(\d+:\d+)', start) is None or re.search(r'(\d+:\d+)', end) is None:
                        return 'Syntax error in parameter: "' + parameter + '", use XX:XX format.'
                    if is_valid_date_hour('hour', start):
                        dict_intent['start'] = start
                    else:
                        return 'ERROR: The informed time in "start" is not valid'
                    if is_valid_date_hour('hour', end):
                        dict_intent['end'] = end
                    else:
                        return 'ERROR: The informed time in "end" is not valid'

                elif "date('" in dict_intent[parameter] and "')" in dict_intent[parameter] and "date('" in dict_intent['end'] and "')" in dict_intent['end']:
                    start = re.search(r"'(.*)'", dict_intent[parameter]).group(1)
                    end = re.search(r"'(.*)'", dict_intent['end']).group(1)
                    if re.search(r'(\d+/\d+/\d+)', start) is None or '-' in start:
                        return 'ERROR: Use date format: xx/xx/xxxx'
                    else:
                        if is_valid_date_hour('date', start):
                            dict_intent['start'] = start
                        else:
                            return 'ERROR: The informed date in "start" is not valid'
                    if re.search(r'(\d+/\d+/\d+)', end) is None or '-' in end:
                        return 'ERROR: Use date format: xx/xx/xxxx'
                    else:
                        if is_valid_date_hour('date', end):
                            dict_intent['end'] = end
                        else:
                            return 'ERROR: The informed date in "end" is not valid'
                elif "datetime('" in dict_intent[parameter] and "')" in dict_intent[parameter] and "datetime('" in dict_intent['end'] and "')" in dict_intent['end']:
                    start = re.search(r"'(.*)'", dict_intent[parameter]).group(1)
                    end = re.search(r"'(.*)'", dict_intent['end']).group(1)
                    date, hour = start.split('-')
                    if re.search(r'(\d+/\d+/\d+-\d+:\d+)', start) is None:
                        return 'ERROR: Use datetime format: xx/xx/xxxx-xx:xx'
                    else:
                        if is_valid_date_hour('date', date):
                            if is_valid_date_hour('hour', hour):
                                dict_intent['start'] = start
                            else:
                                return 'ERROR: The informed time in "start" is not valid'
                        else:
                            return 'ERROR: The informed date in "start" is not valid'
                    date, hour = end.split('-')
                    if re.search(r'(\d+/\d+/\d+-\d+:\d+)', end) is None:
                        return 'ERROR: Use datetime format: xx/xx/xxxx-xx:xx'
                    else:
                        if is_valid_date_hour('date', date):
                            if is_valid_date_hour('hour', hour):
                                dict_intent['end'] = end
                            else:
                                return 'ERROR: The informed time in "end" is not valid'
                        else:
                            return 'ERROR: The informed date in "end" is not valid'
                else:
                    return 'Syntax error in parameter: "start" or "end".'
            else:
                return 'Syntax error: "start" and "end" parameters must be used together'
        elif parameter == 'end':
            if parameter == 'end' and 'start' not in indices:
                return 'Syntax error: "start" and "end" parameters must be used together'

    return send_to_translate(dict_intent)


def process_intent_nat11(dict_intent, intent_type):
    requires = ['from', 'to', 'del', 'add']
    indices = list(dict_intent.keys())
    required = check_parameters(requires, indices)
    if required is not True:
        return "ERROR: The following parameters are mandatory: " + str(required)
    dict_intent['protocol'] = 'all'
    for parameter in indices:
        if parameter == 'from' or parameter == 'to':
            if "endpoint('" in dict_intent[parameter] and "')" in dict_intent[parameter]:
                value = re.search(r"'(.*)'", dict_intent[parameter]).group(1)
                if is_valid_ip(value):
                    dict_intent[parameter] = value
                else:
                    result = identify_value(parameter, dict_intent[parameter])
                    if not result:
                        return 'Not possible translate parameter "' + parameter + ': ' + dict_intent[parameter] + '"'
                    else:
                        dict_intent[parameter] = result
            else:
                return 'Syntax error in parameter: '+parameter
        elif parameter == 'for':
            if "port('" in dict_intent[parameter] and "')" in dict_intent[parameter]:
                value = re.search(r"'(.*)'", dict_intent[parameter]).group(1)
                protocol, src_port, dst_port = value.split('|')
                if "protocol:" in protocol and "src_port:" in src_port and "dst_port:" in dst_port:
                    _, dict_intent['protocol'] = protocol.split(':')
                    _, dict_intent['from_port'] = src_port.split(':')
                    _, dict_intent['to_port'] = dst_port.split(':')
                else:
                    return 'Flow composition error in parameter: '+parameter
            dict_intent.pop('for')
        elif parameter == 'add' or parameter == 'del':
            if 'firewall' in dict_intent[parameter] or 'middlebox' in dict_intent[parameter]:
                if ',' in dict_intent[parameter]:
                    list_firewall = re.search(r"'(.*)'", dict_intent[parameter]).group(1)
                    list_firewall = list_firewall.replace("'", "")
                    dict_intent['devices'] = list_firewall.split(',')
                    if parameter == 'add':
                        dict_intent['apply'] = 'insert'
                        dict_intent.pop('add')
                    else:
                        dict_intent['apply'] = 'remove'
                        dict_intent.pop('del')
                else:
                    value = []
                    value.append(re.search(r"'(.*)'", dict_intent[parameter]).group(1))
                    dict_intent['devices'] = value
                    if parameter == 'add':
                        dict_intent['apply'] = 'insert'
                        dict_intent.pop('add')
                    else:
                        dict_intent['apply'] = 'remove'
                        dict_intent.pop('del')
            else:
                return 'Error in parameter ' + parameter.upper() + '.'
    return send_to_translate(dict_intent)


def process_intent_traffic_shaping(dict_intent, intent_type):
    requires = ['name', 'from', 'to', 'for', 'with', 'order', 'add', 'del']
    indices = list(dict_intent.keys())
    required = check_parameters(requires, indices)
    if required is not True:
        return "ERROR: The following parameters are mandatory: " + str(required)
    for parameter in indices:
        # parameter name
        if parameter == 'name':
            if "text('" in dict_intent[parameter] and "')" in dict_intent[parameter]:
                dict_intent[parameter] = re.search(r"'(.*)'", dict_intent[parameter]).group(1)
            else:
                return 'Syntax error in parameter: "' + parameter + '".'
        # parameters to and from
        elif parameter == 'from' or parameter == 'to':
            if "endpoint('" in dict_intent[parameter] and "')" in dict_intent[parameter]:
                value = re.search(r"'(.*)'", dict_intent[parameter]).group(1)
                dict_intent[parameter] = value
                result = identify_value(parameter, dict_intent[parameter])
                if not result:
                    return 'Not possible translate parameter "' + parameter + ': ' + dict_intent[parameter] + '"'
                else:
                    dict_intent[parameter] = result
            elif "range('" in dict_intent[parameter] and "')" in dict_intent[parameter] and "/" in dict_intent[parameter]:
                value = re.search(r"'(.*)'", dict_intent[parameter]).group(1)
                range, netmask = cidr_to_netmask(value)
                dict_intent[parameter] = range
                dict_intent[parameter + '_mask'] = netmask
            elif dict_intent[parameter] == 'any':
                dict_intent[parameter] = 'all'
            else:
                return 'Syntax error in parameter: ' + parameter
        elif parameter == 'for':
            if "traffic('" in dict_intent[parameter] and "')" in dict_intent[parameter]:
                value = re.search(r"'(.*)'", dict_intent[parameter]).group(1)
            else:
                return 'Syntax error in parameter: ' + parameter
            result = identify_value(parameter, value)
            if not result:
                return 'Error in parameter ' + parameter.upper() + ': "' + value + '"'
            else:
                dict_intent['traffic'] = result
            dict_intent.pop('for')
        elif parameter == 'with':
            if "throughput('" in dict_intent[parameter] and "')" in dict_intent[parameter]:
                value = re.search(r"'(.*)'", dict_intent[parameter]).group(1)
                if 'mbps' in value.lower():
                    dict_intent[parameter] = int(re.search(r'\d+', value).group())
                else:
                    return 'Use "Mbps" in throughout'
            else:
                return 'Syntax error in parameter: "'+parameter
        # parameter order
        elif parameter == 'order':
            if "before('" in dict_intent[parameter] and "')" in dict_intent[parameter]:
                dict_intent['before'] = re.search(r"'(.*)'", dict_intent[parameter]).group(1)
            elif "after('" in dict_intent[parameter] and "')" in dict_intent[parameter]:
                dict_intent['after'] = re.search(r"'(.*)'", dict_intent[parameter]).group(1)
            else:
                return 'Syntax error in parameter: "' + parameter + '".'
            dict_intent.pop('order')
        # parameter logging
        elif parameter == 'logging':
            if 'enable' not in dict_intent[parameter] and 'disable' not in dict_intent[parameter]:
                return 'Syntax error in parameter: "' + parameter + '".'
        elif parameter == 'add' or parameter == 'del':
            if 'firewall' in dict_intent[parameter] or 'middlebox' in dict_intent[parameter]:
                if ',' in dict_intent[parameter]:
                    list_firewall = re.search(r"'(.*)'", dict_intent[parameter]).group(1)
                    list_firewall = list_firewall.replace("'", "")
                    dict_intent['devices'] = list_firewall.split(',')
                    if parameter == 'add':
                        dict_intent['apply'] = 'insert'
                        dict_intent.pop('add')
                    else:
                        dict_intent['apply'] = 'remove'
                        dict_intent.pop('del')
                else:
                    value = []
                    value.append(re.search(r"'(.*)'", dict_intent[parameter]).group(1))
                    dict_intent['devices'] = value
                    if parameter == 'add':
                        dict_intent['apply'] = 'insert'
                        dict_intent.pop('add')
                    else:
                        dict_intent['apply'] = 'remove'
                        dict_intent.pop('del')
            else:
                return 'Error in parameter ' + parameter.upper() + '.'

        # parameter description
        elif parameter == 'description':
            if "text('" in dict_intent[parameter] and "')" in dict_intent[parameter]:
                dict_intent[parameter] = re.search(r"'(.*)'", dict_intent[parameter]).group(1)
            else:
                return 'Syntax error in parameter: "' + parameter + '".'
        # parameters start and end
        elif parameter == 'start':
            if parameter == 'start' and 'end' in indices:
                if "hour('" in dict_intent[parameter] and "')" in dict_intent[parameter] and "hour('" in dict_intent['end'] and "')" in dict_intent['end']:
                    start = re.search(r"'(.*)'", dict_intent[parameter]).group(1)
                    end = re.search(r"'(.*)'", dict_intent['end']).group(1)
                    if is_valid_date_hour('hour', start):
                        dict_intent['start'] = start
                    else:
                        return 'ERROR: The informed time in "start" is not valid'
                    if is_valid_date_hour('hour', end):
                        dict_intent['end'] = end
                    else:
                        return 'ERROR: The informed time in "end" is not valid'

                elif "date('" in dict_intent[parameter] and "')" in dict_intent[parameter] and "date('" in dict_intent['end'] and "')" in dict_intent['end']:
                    start = re.search(r"'(.*)'", dict_intent[parameter]).group(1)
                    end = re.search(r"'(.*)'", dict_intent['end']).group(1)
                    if re.search(r'(\d+/\d+/\d+)', start) is None:
                        return 'ERROR: Use date format: xx/xx/xxxx'
                    else:
                        if is_valid_date_hour('date', start):
                            dict_intent['start'] = start
                        else:
                            return 'ERROR: The informed date in "start" is not valid'
                    if re.search(r'(\d+/\d+/\d+)', end) is None:
                        return 'ERROR: Use date format: xx/xx/xxxx'
                    else:
                        if is_valid_date_hour('date', end):
                            dict_intent['end'] = end
                        else:
                            return 'ERROR: The informed date in "end" is not valid'
                elif "datetime('" in dict_intent[parameter] and "')" in dict_intent[parameter] and "datetime('" in dict_intent['end'] and "')" in dict_intent['end']:
                    start = re.search(r"'(.*)'", dict_intent[parameter]).group(1)
                    end = re.search(r"'(.*)'", dict_intent['end']).group(1)
                    date, hour = start.split('-')
                    if re.search(r'(\d+/\d+/\d+-\d+:\d+)', start) is None:
                        return 'ERROR: Use datetime format: xx/xx/xxxx-xx:xx'
                    else:
                        if is_valid_date_hour('date', date):
                            if is_valid_date_hour('hour', hour):
                                dict_intent['start'] = start
                            else:
                                return 'ERROR: The informed time in "start" is not valid'
                        else:
                            return 'ERROR: The informed date in "start" is not valid'
                    date, hour = end.split('-')
                    if re.search(r'(\d+/\d+/\d+-\d+:\d+)', end) is None:
                        return 'ERROR: Use datetime format: xx/xx/xxxx-xx:xx'
                    else:
                        if is_valid_date_hour('date', date):
                            if is_valid_date_hour('hour', hour):
                                dict_intent['end'] = end
                            else:
                                return 'ERROR: The informed time in "end" is not valid'
                        else:
                            return 'ERROR: The informed date in "end" is not valid'
                else:
                    return 'Syntax error in parameter: "start" or "end".'
            else:
                return 'Syntax error: "start" and "end" parameters must be used together'
        elif parameter == 'end':
            if parameter == 'end' and 'start' not in indices:
                return 'Syntax error: "start" and "end" parameters must be used together'

    return send_to_translate(dict_intent)


def process_intent_dst_route(dict_intent, intent_type):
    requires = ['from', 'to', 'add', 'del']
    indices = list(dict_intent.keys())
    required = check_parameters(requires, indices)
    if required is not True:
        return "ERROR: The following parameters are mandatory: " + str(required)
    for parameter in indices:
        if parameter == 'to':
            if "endpoint('" in dict_intent[parameter] and "')" in dict_intent[parameter]:
                value = re.search(r"'(.*)'", dict_intent[parameter]).group(1)
                dict_intent[parameter] = value
                result = identify_value(parameter, dict_intent[parameter])
                if not result:
                    return 'Not possible translate parameter "' + parameter + ': ' + dict_intent[parameter] + '"'
                else:
                    dict_intent[parameter] = result
                    dict_intent['to_mask'] = '255.255.255.255'
            elif "range('" in dict_intent[parameter] and "')" in dict_intent[parameter]:
                value = re.search(r"'(.*)'", dict_intent[parameter]).group(1)
                range, netmask = cidr_to_netmask(value)
                dict_intent[parameter] = range
                dict_intent[parameter + '_mask'] = netmask
            else:
                return 'Syntax error in parameter: ' + parameter
        elif parameter == 'from':
            if "gateway('" in dict_intent[parameter] and "')" in dict_intent[parameter]:
                value = re.search(r"'(.*)'", dict_intent[parameter]).group(1)
                dict_intent[parameter] = value
                result = identify_value(parameter, dict_intent[parameter])
                if not result:
                    return 'Not possible translate parameter "' + parameter + ': ' + dict_intent[parameter] + '"'
                else:
                    dict_intent['gateway'] = result
        elif parameter == 'add' or parameter == 'del':
            if 'firewall' in dict_intent[parameter] or 'middlebox' in dict_intent[parameter]:
                if ',' in dict_intent[parameter]:
                    list_firewall = re.search(r"'(.*)'", dict_intent[parameter]).group(1)
                    list_firewall = list_firewall.replace("'", "")
                    dict_intent['devices'] = list_firewall.split(',')
                    if parameter == 'add':
                        dict_intent['apply'] = 'insert'
                        dict_intent.pop('add')
                    else:
                        dict_intent['apply'] = 'remove'
                        dict_intent.pop('del')
                else:
                    value = []
                    value.append(re.search(r"'(.*)'", dict_intent[parameter]).group(1))
                    dict_intent['devices'] = value
                    if parameter == 'add':
                        dict_intent['apply'] = 'insert'
                        dict_intent.pop('add')
                    else:
                        dict_intent['apply'] = 'remove'
                        dict_intent.pop('del')
            else:
                return 'Error in parameter ' + parameter.upper() + '.'
    return send_to_translate(dict_intent)


def process_intent_natn1(dict_intent, intent_type):
    requires = ['from', 'to', 'add', 'del']
    indices = list(dict_intent.keys())
    required = check_parameters(requires, indices)
    if required is not True:
        return "ERROR: The following parameters are mandatory: " + str(required)
    for parameter in indices:
        if parameter == 'from':
            if "range('" in dict_intent[parameter] and "')" in dict_intent[parameter]:
                value = re.search(r"'(.*)'", dict_intent[parameter]).group(1)
                range, netmask = cidr_to_netmask(value)
                dict_intent[parameter] = range
                dict_intent[parameter + '_mask'] = netmask
            else:
                return 'Syntax error in parameter: ' + parameter
        elif parameter == 'to':
            if "endpoint('" in dict_intent[parameter] and "')" in dict_intent[parameter]:
                value = re.search(r"'(.*)'", dict_intent[parameter]).group(1)
                dict_intent[parameter] = value
                result = identify_value(parameter, dict_intent[parameter])
                if not result:
                    return 'Not possible translate parameter "' + parameter + ': ' + dict_intent[parameter] + '"'
                else:
                    dict_intent[parameter] = result
        elif parameter == 'add' or parameter == 'del':
            if 'firewall' in dict_intent[parameter] or 'middlebox' in dict_intent[parameter]:
                if ',' in dict_intent[parameter]:
                    list_firewall = re.search(r"'(.*)'", dict_intent[parameter]).group(1)
                    list_firewall = list_firewall.replace("'", "")
                    dict_intent['devices'] = list_firewall.split(',')
                    if parameter == 'add':
                        dict_intent['apply'] = 'insert'
                        dict_intent.pop('add')
                    else:
                        dict_intent['apply'] = 'remove'
                        dict_intent.pop('del')
                else:
                    value = []
                    value.append(re.search(r"'(.*)'", dict_intent[parameter]).group(1))
                    dict_intent['devices'] = value
                    if parameter == 'add':
                        dict_intent['apply'] = 'insert'
                        dict_intent.pop('add')
                    else:
                        dict_intent['apply'] = 'remove'
                        dict_intent.pop('del')
            else:
                return 'Error in parameter ' + parameter.upper() + '.'
    return send_to_translate(dict_intent)


def process_intent_url_filter(dict_intent, intent_type):
    requires = ['name', 'from', 'to', 'allow', 'block', 'order', 'add', 'del']
    indices = list(dict_intent.keys())
    required = check_parameters(requires, indices)
    if required is not True:
        return "ERROR: The following parameters are mandatory: " + str(required)
    for parameter in indices:
        # parameter name
        if parameter == 'name':
            if "text('" in dict_intent[parameter] and "')" in dict_intent[parameter]:
                dict_intent[parameter] = re.search(r"'(.*)'", dict_intent[parameter]).group(1)
            else:
                return 'Syntax error in parameter: "' + parameter + '".'
        # parameters from and to
        elif parameter == 'from':
            if "endpoint('" in dict_intent[parameter] and "')" in dict_intent[parameter]:
                value = re.search(r"'(.*)'", dict_intent[parameter]).group(1)
                dict_intent[parameter] = value
                result = identify_value(parameter, dict_intent[parameter])
                if not result:
                    return 'Not possible translate parameter "' + parameter + ': ' + dict_intent[parameter] + '"'
                else:
                    dict_intent[parameter] = result
            elif "range('" in dict_intent[parameter] and "')" in dict_intent[parameter]:
                value = re.search(r"'(.*)'", dict_intent[parameter]).group(1)
                range, netmask = cidr_to_netmask(value)
                dict_intent[parameter] = range
                dict_intent[parameter + '_mask'] = netmask
            elif dict_intent[parameter] == 'any':
                dict_intent[parameter] = 'all'
            else:
                return 'Syntax error in parameter: ' + parameter
        elif parameter == 'to':
            if "endpoint('" in dict_intent[parameter] and "')" in dict_intent[parameter]:
                value = re.search(r"'(.*)'", dict_intent[parameter]).group(1)
                dict_intent[parameter] = value
            elif "category('" in dict_intent[parameter] and "')" in dict_intent[parameter]:
                value = re.search(r"'(.*)'", dict_intent[parameter]).group(1)
                dict_intent[parameter] = value
            elif dict_intent[parameter] == 'any':
                dict_intent[parameter] = 'all'
        # parameters allow e block
        elif parameter == 'allow' or parameter == 'block':
            if "traffic('" in dict_intent[parameter] and "')" in dict_intent[parameter]:
                value = re.search(r"'(.*)'", dict_intent[parameter]).group(1)
                if value == 'all':
                    dict_intent['traffic'] = 'all'
                elif value == 'icmp':
                    dict_intent['traffic'] = 'icmp'
                else:
                    result = identify_value(parameter, value)
                    if result is False:
                        return 'Error in parameter ' + parameter.upper() + ': "' + value + '"'
                    else:
                        dict_intent['traffic'] = result
            else:
                return 'Syntax error in parameter: "' + parameter + '".'
            if parameter == 'allow':
                dict_intent['rule'] = 'allow'
                dict_intent.pop('allow')
            else:
                dict_intent['rule'] = 'block'
                dict_intent.pop('block')
        # parameter order
        elif parameter == 'order':
            if "before('" in dict_intent[parameter] and "')" in dict_intent[parameter]:
                dict_intent['before'] = re.search(r"'(.*)'", dict_intent[parameter]).group(1)
            elif "after('" in dict_intent[parameter] and "')" in dict_intent[parameter]:
                dict_intent['after'] = re.search(r"'(.*)'", dict_intent[parameter]).group(1)
            else:
                return 'Syntax error in parameter: "' + parameter + '".'
            dict_intent.pop('order')
        elif parameter == 'add' or parameter == 'del':
            if 'firewall' in dict_intent[parameter] or 'middlebox' in dict_intent[parameter]:
                if ',' in dict_intent[parameter]:
                    list_firewall = re.search(r"'(.*)'", dict_intent[parameter]).group(1)
                    list_firewall = list_firewall.replace("'", "")
                    dict_intent['devices'] = list_firewall.split(',')
                    if parameter == 'add':
                        dict_intent['apply'] = 'insert'
                        dict_intent.pop('add')
                    else:
                        dict_intent['apply'] = 'remove'
                        dict_intent.pop('del')
                else:
                    value = []
                    value.append(re.search(r"'(.*)'", dict_intent[parameter]).group(1))
                    dict_intent['devices'] = value
                    if parameter == 'add':
                        dict_intent['apply'] = 'insert'
                        dict_intent.pop('add')
                    else:
                        dict_intent['apply'] = 'remove'
                        dict_intent.pop('del')
            else:
                return 'Error in parameter ' + parameter.upper() + '.'
    return send_to_translate(dict_intent)


def send_to_translate(dict_intent):
    result = "\n"
    flag = 0
    print(dict_intent)
    rule_status = check_rule(dict_intent)
    if rule_status == 'OK':
        with open("etc/services_enable.conf", 'r') as archive:
            for line in archive:
                if line[0:1] != "#" and line[0:1] != " " and line[0:1] != "\n":
                    flag = 1
                    try:
                        name, function = line.split()
                    except ValueError:
                        return "ERROR: Check the file 'services_enable.conf'"
                    for device in dict_intent['devices']:
                        if device == name:
                            result = result + "--> Return of module " + name.upper()
                            result = result + '\n----------------------------------\n'
                            with ClusterRpcProxy(CONFIG) as rpc:
                                command = "rpc." + function + "(dict_intent)"
                                result = result + eval(command) + "\n"
                                if "ERROR" not in result:
                                    result = result + '\n\nCommands applied in the firewall ' + name.upper() + ': OK\n'
                                result = result + '----------------------------------\n'
        if flag == 1:
            if 'ERROR ORDER' in result:
                remove_error_rule(dict_intent)
            else:
                return result
        else:
            return "ERROR: Check the file 'services_enable.conf'"
    elif 'ERROR NAME' or 'ERROR DUPLICATE' in rule_status:
        return rule_status


def process_intent(intent, role):
    with open(intent_archive, 'w+b') as archive:
        archive.write(intent)
    archive = open(intent_archive, 'r')
    tmp_intent = archive.readlines()[get_line('define intent'):]
    if len(tmp_intent) == 0:
        return "Intent is incomplete or empty"
    _, _, intent_type = tmp_intent[0].split()
    intent_type = intent_type[0:intent_type.index(':')]
    final_intent = {'intent_type': intent_type.lower()}
    for line in tmp_intent[1:]:
        if '#' not in line[0:5] and line[0:1] != "\n":
            try:
                key, value = line.split(None, 1)
                key = key.lower()
                final_intent[key] = value.lower()
            except ValueError:
                return 'Incomplete intent for type "'+intent_type.upper()+'", see /help'
    if intent_type == 'acl':
        if role == 'super-admin':
            return process_intent_acl(final_intent, intent_type)
        else:
            return "User role " + role.upper() + " can't manipulate ACL intents"
    elif intent_type == 'nat_1to1':
        if role == 'super-admin' or role == 'admin':
            return process_intent_nat11(final_intent, intent_type)
        else:
            return "User role " + role.upper() + " can't manipulate NAT intents"
    elif intent_type == 'traffic_shaping':
        if role == 'super-admin' or role == 'admin' or role == 'user':
            return process_intent_traffic_shaping(final_intent, intent_type)
        else:
            return "User role " + role.upper() + " can't manipulate Traffic Shaping intents"
    elif intent_type == 'dst_route':
        if role == 'super-admin':
            return process_intent_dst_route(final_intent, intent_type)
        else:
            return "User role " + role.upper() + " can't manipulate Traffic Shaping intents"
    elif intent_type == 'nat_nto1':
        if role == 'super-admin':
            return process_intent_natn1(final_intent, intent_type)
        else:
            return "User role " + role.upper() + " can't manipulate Traffic Shaping intents"
    elif intent_type == 'url_filter':
        if role == 'super-admin':
            return process_intent_url_filter(final_intent, intent_type)
        else:
            return "User role " + role.upper() + " can't manipulate Traffic Shaping intents"

    else:
        return "Unrecognized intent type, see /help"


@app.route('/', methods=['POST'])
@auth.login_required
def receive_intent():
    request.get_data()
    profile = getProfile(apiProfile.Users, auth.username())
    response = process_intent(request.data, profile["Role"])
    return response+"\n", 200


@auth.verify_password
def verify_password(username, password):
    user = getProfile(apiProfile.Users, username)
    if user is None:
        return False
    return pbkdf2_sha256.verify(password, user["PasswordHash"])


def getProfile(Users, username):
    for user in Users:
        if username == user["UserName"]:
            return user


if __name__ == '__main__':
    app.run()


