from jinja2 import Environment, FileSystemLoader
from netaddr import IPAddress, IPNetwork
from yamlreader import yaml_load
from nameko.rpc import rpc, RpcProxy
import calendar
from nameko.standalone.rpc import ClusterRpcProxy


CONFIG = {'AMQP_URI': "amqp://guest:guest@localhost:5672"}


def check_ip_network(ip, network):
    if ip == 'all':
        return False
    if IPAddress(ip) in IPNetwork(network):
        return True
    else:
        return False


# function to ensure that the dictionary has all the necessary fields
def check_values(dict_intent):
    if dict_intent['intent_type'] == 'acl':
        parameters = ['from', 'to', 'rule', 'traffic', 'apply']
    elif dict_intent['intent_type'] == 'nat_1to1':
        parameters = ['from', 'to', 'protocol', 'apply']
    elif dict_intent['intent_type'] == 'traffic_shaping':
        parameters = ['name', 'from', 'to', 'with', 'traffic', 'apply']
    elif dict_intent['intent_type'] == 'dst_route':
        parameters = ['from', 'to', 'apply']
    elif dict_intent['intent_type'] == 'nat_nto1':
        parameters = ['from', 'to', 'apply']
    elif dict_intent['intent_type'] == 'url_filter':
        parameters = ['name', 'from', 'to', 'rule', 'apply']
    else:
        return "CISCO TRANSLATOR: Intent type not supported"
    for parameter in parameters:
        if parameter not in dict_intent:
            return 'CISCO TRANSLATOR: ' + parameter.upper() + 'parameter is missing'
    return True


def define_order(dict_intent):
    line = 0
    if dict_intent['intent_type'] == 'acl':
        file = 'rules/cisco_acls'
    elif dict_intent['intent_type'] == 'traffic_shaping':
        file = 'rules/cisco_ts'
    else:
        return "CISCO MODULE: Order not found"
    with open(file) as archive:
        if dict_intent['apply'] == 'insert':
            if 'after' in dict_intent:
                if dict_intent['after'] == 'all-intents':
                    for line_num, l in enumerate(archive, 0):
                        line = line_num
                    line = line + 1
                else:
                    for line_num, l in enumerate(archive, 0):
                        if "'name': '" + dict_intent['after'] + "'" in l:
                            line = line_num + 1
            elif 'before' in dict_intent:
                if dict_intent['before'] == 'all-intents':
                    line = 1
                else:
                    for line_num, l in enumerate(archive, 0):
                        if "'name': '" + dict_intent['before'] + "'" in l:
                            line = line_num
        else:
            for line_num, l in enumerate(archive, 0):
                if "'name': '" + dict_intent['name'] + "'" in l:
                    line = line_num
    archive.close()
    if line != 0:
        archive = open(file)
        lines = archive.readlines()
        archive.close()
        if dict_intent['apply'] == 'insert':
            lines.insert(line, str(dict_intent) + "\n")
            if dict_intent['intent_type'] == 'traffic_shaping':
                lines.insert(line + 1, str(dict_intent) + "\n")
        else:
            lines.pop(line)
            if dict_intent['intent_type'] == 'traffic_shaping':
                lines.pop(line - 1)
        archive = open(file, 'w')
        archive.writelines(lines)
        archive.close()

    return line


def process_acl(dict_intent):
    # loading YAML file with firewall settings
    config = yaml_load('cisco_config.yml')
    # identify interface
    for interface in config['INTERFACES']:
        if check_ip_network(dict_intent['from'], interface['addr']):
            dict_intent['from_interface'] = interface['name']
        elif check_ip_network(dict_intent['to'], interface['addr']):
            dict_intent['to_interface'] = interface['name']
    if 'from_interface' not in dict_intent and 'to_interface' not in dict_intent:
        if dict_intent['from'] != 'all' and dict_intent['to'] != 'all':
            return "CISCO TRANSLATOR: Unrecognized network"
        else:
            dict_intent['from_interface'] = 'inside'
    dict_intent['from_interface'] = 'inside'
    if dict_intent['from'] == 'all':
        dict_intent['from'] = 'any'
    if dict_intent['to'] == 'all':
        dict_intent['to'] = 'any'
    order = define_order(dict_intent)
    if order != 0:
        dict_intent['order'] = order
    else:
        return 'CISCO TRANSLATOR - ERROR ORDER: It was not possible to determine the order by name in order parameter'

    # translate allow/block
    if dict_intent['rule'] == 'allow':
        dict_intent['rule'] = 'permit'
    else:
        dict_intent['rule'] = 'deny'
    # translate protocol/port
    if dict_intent['traffic'] == 'all':
        dict_intent['traffic'] = 'ip'
    elif dict_intent['traffic'] == 'icmp':
        dict_intent['traffic'] = 'icmp'
    else:
        protocol, port = dict_intent['traffic'].split('/')
        dict_intent['traffic'] = protocol
        dict_intent['traffic_port'] = 'eq ' + port
    # identifies the use of ranges

    if 'from_mask' in dict_intent:
        dict_intent['from'] = dict_intent['from'] + ' ' + dict_intent['from_mask']
    elif dict_intent['from'] != 'any':
        dict_intent['from'] = 'host ' + dict_intent['from']
    if 'to_mask' in dict_intent:
        dict_intent['to'] = dict_intent['to'] + ' ' + dict_intent['to_mask']
    elif dict_intent['to'] != 'any':
        dict_intent['to'] = 'host ' + dict_intent['to']
    # datetime
    if 'start' in dict_intent:
        dict_intent['time_range'] = 'time-range ' + dict_intent['name']
        if '-' in dict_intent['start'] and '-' in dict_intent['end']:
            date_start, dict_intent['hour_start'] = dict_intent['start'].split('-')
            date_end, dict_intent['hour_end'] = dict_intent['end'].split('-')
            d, m, y = date_start.split('/')
            m = calendar.month_abbr[int(m)]
            dict_intent['date_start'] = d + ' ' + m + ' ' + y
            d, m, y = date_end.split('/')
            m = calendar.month_abbr[int(m)]
            dict_intent['date_end'] = d + ' ' + m + ' ' + y
        elif '/' in dict_intent['start'] and '/' in dict_intent['end']:
            dict_intent['hour_start'] = '00:00'
            dict_intent['hour_end'] = '23:59'
            d, m, y = dict_intent['start'].split('/')
            m = calendar.month_abbr[int(m)]
            dict_intent['date_start'] = d + ' ' + m + ' ' + y
            d, m, y = dict_intent['end'].split('/')
            m = calendar.month_abbr[int(m)]
            dict_intent['date_end'] = d + ' ' + m + ' ' + y
        else:
            dict_intent['hour_start'] = dict_intent['start']
            dict_intent['hour_end'] = dict_intent['end']
    # logging
    if 'logging' in dict_intent:
        if 'disable' in dict_intent['logging']:
            dict_intent['logging'] = 'log disable'
        else:
            dict_intent['logging'] = ''
    else:
        dict_intent['logging'] = ''
    # other configs
    dict_intent['password'] = config['password']
    # loading and render template jinja2
    file_loader = FileSystemLoader('.')
    env = Environment(loader=file_loader)
    template = env.get_template('cisco_template.j2')
    output = template.render(dict_intent)
    #with ClusterRpcProxy(CONFIG) as rpc_connect:
    #    rpc_connect.cisco_connector.apply_config(config['ip_manage'], config['ssh_port'], config['username'], config['password'], config['device_type'], output)
    return output


def process_nat11(dict_intent):
    # loading YAML file with firewall settings
    if dict_intent['protocol'] == 'all':
        dict_intent['protocol'] = 'any'
    config = yaml_load('cisco_config.yml')
    # identifies interfaces
    for interface in config['INTERFACES']:
        if check_ip_network(dict_intent['from'], interface['addr']):
            dict_intent['from_interface'] = interface['name']
        elif check_ip_network(dict_intent['to'], interface['addr']):
            dict_intent['to_interface'] = interface['name']
        else:
            return 'CISCO TRANSLATOR: IP/Network not recognized'
    # loading and render template jinja2
    file_loader = FileSystemLoader('.')
    env = Environment(loader=file_loader)
    template = env.get_template('cisco_template.j2')
    output = template.render(dict_intent)
    #with ClusterRpcProxy(CONFIG) as rpc_connect:
    #    rpc_connect.cisco_connector.apply_config(config['ip_manage'], config['ssh_port'], config['username'],
    #                                          config['password'], config['device_type'], output)
    return output


def process_traffic_shaping(dict_intent):
    # loading YAML file with firewall settings
    config = yaml_load('cisco_config.yml')
    # converting throughput and rate
    dict_intent['with'] = dict_intent['with'] * 1000000
    dict_intent['rate'] = int(dict_intent['with'] * 0.0005)
    # range/host treatment
    if 'from_mask' in dict_intent:
        dict_intent['from'] = dict_intent['from'] + ' ' + dict_intent['from_mask']
    else:
        dict_intent['from'] = 'host ' + dict_intent['from']
    if 'to_mask' in dict_intent:
        dict_intent['to'] = dict_intent['to'] + ' ' + dict_intent['to_mask']
    else:
        dict_intent['to'] = 'host ' + dict_intent['to']
    # define order
    order = define_order(dict_intent)
    if order != 0:
        dict_intent['order'] = order
    else:
        return 'CISCO TRANSLATOR - ERROR ORDER: It was not possible to determine the order by name in order parameter'

    # translate protocol/port
    if dict_intent['traffic'] == 'all':
        dict_intent['traffic'] = 'ip'
    elif dict_intent['traffic'] == 'icmp':
        dict_intent['traffic'] = 'icmp'
    else:
        protocol, port = dict_intent['traffic'].split('/')
        dict_intent['traffic'] = protocol
        dict_intent['traffic_port'] = 'eq ' + port
    # loading and render template jinja2
    file_loader = FileSystemLoader('.')
    env = Environment(loader=file_loader)
    template = env.get_template('cisco_template.j2')
    output = template.render(dict_intent)
    #with ClusterRpcProxy(CONFIG) as rpc_connect:
    #    rpc_connect.cisco_connector.apply_config(config['ip_manage'], config['ssh_port'], config['username'],
    #                                           config['password'], config['device_type'], output)
    return output


def process_dst_route(dict_intent):
    # loading YAML file with firewall settings
    config = yaml_load('cisco_config.yml')
    if 'to_mask' in dict_intent:
        dict_intent['to'] = dict_intent['to'] + ' ' + dict_intent['to_mask']
    # loading and render template jinja2
    file_loader = FileSystemLoader('.')
    env = Environment(loader=file_loader)
    template = env.get_template('cisco_template.j2')
    output = template.render(dict_intent)
    #with ClusterRpcProxy(CONFIG) as rpc_connect:
    #    rpc_connect.cisco_connector.apply_config(config['ip_manage'], config['ssh_port'], config['username'],
    #                                          config['password'], config['device_type'], output)
    return output


def process_natn1(dict_intent):
    # loading YAML file with firewall settings
    config = yaml_load('cisco_config.yml')
    # identifies interfaces
    dict_intent['name'] = 'obj-' + dict_intent['from']
    if 'from_mask' in dict_intent:
        dict_intent['from'] = dict_intent['from'] + ' ' + dict_intent['from_mask']
    # loading and render template jinja2
    file_loader = FileSystemLoader('.')
    env = Environment(loader=file_loader)
    template = env.get_template('cisco_template.j2')
    output = template.render(dict_intent)
    #with ClusterRpcProxy(CONFIG) as rpc_connect:
    #   rpc_connect.cisco_connector.apply_config(config['ip_manage'], config['ssh_port'], config['username'],
    #                                          config['password'], config['device_type'], output)
    return output


def process_url_filter(dict_intent):
    return 'CISCO TRANSLATOR: URL Filter is not yet supported'


class CiscoService:
    """
        Cisco 5520 Service
        Microservice that translates the information sent by the api to commands applicable in Cisco ASA 5520
        Receive: this function receives a python dictionary, with at least the following information for each processing
        Return:
            - The microservice activates the application module via ssh and returns the result. If any incorrect
            information in the dictionary, the error message is returned
    """
    name = "cisco_translator"
    zipcode_rpc = RpcProxy('cisco_service_translator')

    @rpc
    def translate_intent(self, dict_intent):
        if 'intent_type' in dict_intent:
            output = check_values(dict_intent)
            if output is True:
                if dict_intent['intent_type'] == 'acl':
                    output_service = process_acl(dict_intent)
                elif dict_intent['intent_type'] == 'nat_1to1':
                    output_service = process_nat11(dict_intent)
                elif dict_intent['intent_type'] == 'traffic_shaping':
                    output_service = process_traffic_shaping(dict_intent)
                elif dict_intent['intent_type'] == 'dst_route':
                    output_service = process_dst_route(dict_intent)
                elif dict_intent['intent_type'] == 'nat_nto1':
                    output_service = process_natn1(dict_intent)
                elif dict_intent['intent_type'] == 'url_filter':
                    output_service = process_url_filter(dict_intent)
                if output_service == 'ERROR':
                    return 'CISCO TRANSLATOR: Error when applying settings'
                else:
                    return output_service
            else:
                return 'CISCO TRANSLATOR: Error in dictionary'
        else:
            return 'CISCO TRANSLATOR: the key "intent_type" is unavailable in the dictionary'
