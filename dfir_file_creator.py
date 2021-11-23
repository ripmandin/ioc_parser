import dfir_parser
import yaml
import os.path


def yaml_report_generate(filename, data):
    with open(f'{os.getcwd()}\\{filename}.yml', 'w') as f:
        yaml.dump(data, f, default_flow_style=False)


def yaml_iocs_generate(data):
    if os.path.exists(f'{os.getcwd()}\\iocs.yml'):
        with open(f'{os.getcwd()}\\iocs.yml') as f:
            iocs = yaml.safe_load(f)
        for ip in data.get('ip'):
            if ip not in iocs.get('ip'):
                iocs['ip'].append(ip)
        for domain in data.get('domains'):
            if domain not in iocs.get('domains'):
                iocs['domains'].append(domain)
        for hash_type in list(data.get('hashes').keys()):
            for h in data.get('hashes').get(f'{hash_type}'):
                if h not in iocs.get('hashes').get(f'{hash_type}'):
                    iocs['hashes'][f'{hash_type}'].append(h)
        with open(f'{os.getcwd()}\\iocs.yml', 'w') as f:
            yaml.dump(iocs, f, default_flow_style=False)
    else:
        with open(f'{os.getcwd()}\\iocs.yml', 'w') as f:
            yaml.dump(data, f, default_flow_style=False)


def docs_create(uri):
    to_yaml = dfir_parser.parse(uri)
    filename = uri.split('/')[-2]
    yaml_report_generate(filename, to_yaml)
    yaml_iocs_generate(to_yaml)