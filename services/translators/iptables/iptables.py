
import re
from jinja2 import Environment, FileSystemLoader
from netaddr import IPAddress, IPNetwork
from yamlreader import yaml_load
from nameko.rpc import rpc, RpcProxy
from nameko.standalone.rpc import ClusterRpcProxy


CONFIG = {'AMQP_URI': "amqp://guest:guest@localhost:5672"}


def check_ip_network(ip, network):
    if ip == 'all':
        return False
    if IPAddress(ip) in IPNetwork(network):
        return True
    else:
        return False


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
        return "IPTABLES TRANSLATOR: Intent type not supported"
    for parameter in parameters:
        if parameter not in dict_intent:
            return 'IPTABLES TRANSLATOR: ' + parameter.upper() + ' parameter is missing'
    return True


def define_order(dict_intent):
    line = 0
    if dict_intent['intent_type'] == 'acl':
        file = 'rules/iptables_acls'
    elif dict_intent['intent_type'] == 'traffic_shaping':
        file = 'rules/iptables_ts'
    else:
        return "IPTABLES MODULE: Order not found"
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
    # loading YAML with iptables settings
    config = yaml_load('iptables_config.yml')

    order = define_order(dict_intent)
    if order != 0:
        dict_intent['order'] = order
    else:
        return 'IPTABLES TRANSLATOR - ERROR ORDER: It was not possible to determine the order by name in order ' \
               'parameter '

    # identifies chain
    for interface in config['INTERFACES']:
        if check_ip_network(dict_intent['from'], interface['addr']):
            dict_intent['from_interface'] = interface['name']
        elif check_ip_network(dict_intent['to'], interface['addr']):
            dict_intent['to_interface'] = interface['name']
        if dict_intent['from'] == re.search(r'(.*)/', str(interface['addr'])).group(1):
            dict_intent['chain'] = 'OUTPUT'
        elif dict_intent['to'] == re.search(r'(.*)/', str(interface['addr'])).group(1):
            dict_intent['chain'] = 'INPUT'
        else:
            dict_intent['chain'] = 'OUTPUT'

    if dict_intent['from'] == 'all':
        dict_intent['from'] = '0.0.0.0/0.0.0.0'
    if dict_intent['to'] == 'all':
        dict_intent['to'] = '0.0.0.0/0.0.0.0'

    # translate allow/block
    if dict_intent['rule'] == 'allow':
        dict_intent['rule'] = 'ACCEPT'
    else:
        dict_intent['rule'] = 'DROP'
    # translate protocol/port
    if dict_intent['traffic'] == 'all':
        dict_intent['traffic'] = 'all'
    elif dict_intent['traffic'] == 'icmp':
        dict_intent['traffic'] = 'icmp'
    else:
        dict_intent['traffic'], dict_intent['traffic_port'] = dict_intent['traffic'].split('/')
        dict_intent['traffic_port'] = '--dport ' + dict_intent['traffic_port']
    if 'from_mask' in dict_intent:
        dict_intent['from'] = dict_intent['from'] + '/' + dict_intent['from_mask']
    if 'to_mask' in dict_intent:
        dict_intent['to'] = dict_intent['to'] + '/' + dict_intent['to_mask']
    # print(dict_intent)
    # other configs
    dict_intent['password'] = config['password']
    file_loader = FileSystemLoader('.')
    env = Environment(loader=file_loader)
    template = env.get_template('iptables_template.j2')
    output = template.render(dict_intent)
    with ClusterRpcProxy(CONFIG) as rpc_connect:
        rpc_connect.linux_connector.apply_config(config['ip_manage'], config['ssh_port'], config['username'], config['password'],
                                               config['device_type'], output, 'iptables')
    return output


def process_nat11(dict_intent):
    config = yaml_load('iptables_config.yml')
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
    template = env.get_template('iptables_template.j2')
    output = template.render(dict_intent)
    with ClusterRpcProxy(CONFIG) as rpc_connect:
        rpc_connect.linux_connector.apply_config(config['ip_manage'], config['ssh_port'], config['username'],
                                               config['password'], config['device_type'], output, 'iptables')
    return output


def process_traffic_shaping(dict_intent):
    return 'IPTABLES TRANSLATOR: Traffic shaping is not yet supported'


def process_dst_route(dict_intent):
    # loading YAML file with firewall settings
    config = yaml_load('iptables_config.yml')
    # loading and render template jinja2
    for interface in config['INTERFACES']:
        if check_ip_network(dict_intent['from'], interface['addr']):
            dict_intent['interface'] = interface['name']
    if 'interface' not in dict_intent:
        return "IPTABLES TRANSLATOR: Unrecognized gateway"
    dict_intent['to'] = dict_intent['to'] + '/' + str(IPAddress(dict_intent['to_mask']).netmask_bits())
    file_loader = FileSystemLoader('.')
    env = Environment(loader=file_loader)
    template = env.get_template('iptables_template.j2')
    output = template.render(dict_intent)
    with ClusterRpcProxy(CONFIG) as rpc_connect:
        rpc_connect.linux_connector.apply_config(config['ip_manage'], config['ssh_port'], config['username'],
                                              config['password'], config['device_type'], output)
    return output


def process_natn1(dict_intent):
    # loading YAML file with firewall settings
    config = yaml_load('iptables_config.yml')
    # identifies interfaces
    for interface in config['INTERFACES']:
        if check_ip_network(dict_intent['to'], interface['addr']):
            dict_intent['interface'] = interface['name']
    if 'interface' not in dict_intent:
        return "IPTABLES TRANSLATOR: Unrecognized gateway"
    dict_intent['from'] = dict_intent['from'] + '/' + str(IPAddress(dict_intent['from_mask']).netmask_bits())
    # loading and render template jinja2
    file_loader = FileSystemLoader('.')
    env = Environment(loader=file_loader)
    template = env.get_template('iptables_template.j2')
    output = template.render(dict_intent)
    with ClusterRpcProxy(CONFIG) as rpc_connect:
        rpc_connect.linux_connector.apply_config(config['ip_manage'], config['ssh_port'], config['username'],
                                              config['password'], config['device_type'], output)
    return output


def process_url_filter(dict_intent):
    return 'IPTABLES TRANSLATOR: URL Filter is not yet supported'


class IptablesService:
    """
        IPTABLES Service
        Microservice that translates the information sent by the api to commands applicable in IPTABLES
        Receive: this function receives a python dictionary, with at least the following information for each processing
        Return:
            - The microservice activates the application module via ssh and returns the result. If any incorrect
            information in the dictionary, the error message is returned
        """
    name = "iptables_translator"
    zipcode_rpc = RpcProxy('iptables_service_translator')

    @rpc
    def translate_intent(self, dict_intent):
        if 'intent_type' in dict_intent:
            output = check_values(dict_intent)
            if output is True:
                if dict_intent['intent_type'] == 'acl':
                    return process_acl(dict_intent)
                elif dict_intent['intent_type'] == 'nat_1to1':
                    return process_nat11(dict_intent)
                elif dict_intent['intent_type'] == 'traffic_shaping':
                    return process_traffic_shaping(dict_intent)
                elif dict_intent['intent_type'] == 'dst_route':
                    return process_dst_route(dict_intent)
                elif dict_intent['intent_type'] == 'nat_nto1':
                    return process_natn1(dict_intent)
                elif dict_intent['intent_type'] == 'url_filter':
                    return process_url_filter(dict_intent)
            else:
                return output
        else:
            return 'IPTABLES TRANSLATOR: the key "intent_type" is unavailable in the dictionary'


