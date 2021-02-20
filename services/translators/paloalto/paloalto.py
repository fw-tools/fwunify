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
        return "PALOALTO TRANSLATOR: Intent type not supported"
    for parameter in parameters:
        if parameter not in dict_intent:
            return 'PALOALTO TRANSLATOR: ' + parameter.upper() + 'parameter is missing'
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
                if dict_intent['after'] == 'all':
                    for line_num, l in enumerate(archive, 0):
                        line = line_num
                    line = line + 1
                else:
                    for line_num, l in enumerate(archive, 0):
                        if "'name': '" + dict_intent['after'] + "'" in l:
                            line = line_num + 1
            elif 'before' in dict_intent:
                if dict_intent['before'] == 'all':
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


def process_url_filter(dict_intent):
    # loading YAML file with firewall settings
    config = yaml_load('paloalto_config.yml')
    if dict_intent['from'] == 'all':
        dict_intent['from'] = 'any'
    # identifies the use of ranges
    if 'from_mask' in dict_intent:
        dict_intent['from'] = dict_intent['from'] + ' ' + dict_intent['from_mask']
    # other configs
    dict_intent['password'] = config['password']
    # loading and render template jinja2
    file_loader = FileSystemLoader('.')
    env = Environment(loader=file_loader)
    template = env.get_template('paloalto_template.j2')
    output = template.render(dict_intent)
    #with ClusterRpcProxy(CONFIG) as rpc_connect:
    #    rpc_connect.cisco_connector.apply_config(config['ip_manage'], config['ssh_port'], config['username'], config['password'], config['device_type'], output)
    return output


def process_nat11(dict_intent):
    return 'PALOALTO TRANSLATOR: NAT 1to1 is not yet supported'


def process_traffic_shaping(dict_intent):
    return 'PALOALTO TRANSLATOR: Traffic Shaping is not yet supported'


def process_dst_route(dict_intent):
    return 'PALOALTO TRANSLATOR: Route is not yet supported'


def process_natn1(dict_intent):
    return 'PALOALTO TRANSLATOR: NAT Nto1 is not yet supported'


def process_acl(dict_intent):
    return 'PALOALTO TRANSLATOR: URL Filter is not yet supported'


class PaloaltoService:
    """
        Palo alto
        Microservice that translates the information sent by the api to commands applicable in Palo Alto
        Receive: this function receives a python dictionary, with at least the following information for each processing
        
        Return: The microservice activates the application module via ssh and returns the result. If any incorrect
        information in the dictionary, the error message is returned
    """
    name = "paloalto_translator"
    zipcode_rpc = RpcProxy('paloalto_service_translator')

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
                    return 'PALOALTO TRANSLATOR: Error when applying settings'
                else:
                    return output_service
            else:
                return 'PALOALTO TRANSLATOR: Error in dictionary'
        else:
            return 'PALOALTO TRANSLATOR: the key "intent_type" is unavailable in the dictionary'
