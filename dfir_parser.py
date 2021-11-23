from bs4 import BeautifulSoup
import re
import requests


# из-за того, что в новых отчетах тег <pre> разбивается (видимо чтобы не парсили)
# пришлось сделать через обрезку текста страницы по заголовкам Network, File|Endpoint, Detection
def tag_finder(data, regexp):
    try:
        return data.find(re.search(regexp, data).group())
    except AttributeError:
        return 0


def get_net_text_new(uri):
    print(f"Parsing {uri}...")
    html = requests.get(uri)
    soup = BeautifulSoup(html.text, 'lxml')
    s = soup.text
    net = tag_finder(s, r'Network:?\n')
    files = tag_finder(s, r'Files?:?\n|Endpoints?:?\n')
    detect = tag_finder(s, r'Detections?:?\n')
    if net == files == detect == 0:
        net_parse_area = s
    elif net < files:
        net_parse_area = s[net: files]
    else:
        net_parse_area = s[net: detect]
    # убираем значения портов и квадратные скобки в ip-адресе, а также http и www для парсинга доменов
    return re.sub(r'[\[\]]|([|:]\d{1,5})|https?://|www', '', net_parse_area)


# для парсинг старых репортов до 15 ноября 2021 нужен другой алгоритм из-за изменения структуры сайта
def get_net_text_old(uri):
    print(f"Parsing {uri}...")
    html = requests.get(uri)
    soup = BeautifulSoup(html.text, 'lxml')
    s = soup.prettify(formatter=None)
    net = tag_finder(s, r'Network:?\n')
    files = tag_finder(s, r'Files?:?\n|Endpoints?:?\n')
    detect = tag_finder(s, r'Detections?:?\n')
    if net == files == detect == 0:
        begin = soup.find(name=re.compile(r'h?'), text=re.compile(r'IOC.?'))
        net_parse_area = begin.find_next('pre').text
    elif net < files:
        net_parse_area = s[net: files]
    else:
        net_parse_area = s[net: detect]
    return re.sub(r'[\[\]]|([:]\d{1,5})|https?://|www', '', net_parse_area)


def get_hash_text(uri):
    html = requests.get(uri)
    soup = BeautifulSoup(html.text, 'lxml')
    s = soup.prettify(formatter=None)
    net = tag_finder(s, r'Network:?\n')
    files = tag_finder(s, r'Files?:?\n|Endpoints?:?\n')
    detect = tag_finder(s, r'Detections?:?\n')
    if net == files == detect == 0:
        hash_parse_area = s[s.rfind('IOC'): s.rfind('Share this:')]
    elif net < files:
        hash_parse_area = s[files: detect]
    else:
        hash_parse_area = s[files: net]
    return hash_parse_area


# добавил фильтр на особые IP по результатам обработки самого последнего отчета,
# их конечно больше чем 4, но решил не перегружать программу
def get_ips(parsing_data):
    ip_regexp = r'(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)'
    filter_ips = ['0.0.0.0', '127.0.0.0', '127.0.0.1', '255.255.255.255']
    parsed_ips = sorted(list(set(re.findall(ip_regexp, parsing_data))))
    for ip in filter_ips:
        if ip in parsed_ips:
            parsed_ips.remove(ip)
    return parsed_ips


# по причине того что в некоторых случаяъ нельзя отличить доменов от файла, добавлен фильтр на расширения
def get_domains(parsing_data):
    domains = []
    filter_extensions = ['zip', 'txt', 'exe', 'aspx', 'dll', 'tmp', 'dwn',
                         'json', 'ps1', 'xml', 'php', 'js', 'png', 'yml', 'bat']
    parsed_domains = list(set(re.findall(r'[\w.]{1,100}\.[a-z]{2,10}1?', parsing_data)))
    for domain in parsed_domains:
        if any([x in domain for x in filter_extensions]):
            continue
        else:
            domains.append(domain)
    return domains


def get_hashes(parsing_data):
    parsed_md5 = list(set(re.findall(r'\b[a-f0-9]{32}\b', parsing_data, re.I)))
    parsed_sha1 = list(set(re.findall(r'\b[a-f0-9]{40}\b', parsing_data, re.I)))
    parsed_sha256 = list(set(re.findall(r'\b[a-f0-9]{64}\b', parsing_data, re.I)))
    parsed_hashes = {'md5': parsed_md5, 'sha1': parsed_sha1, 'sha256': parsed_sha256}
    return parsed_hashes


def parse(uri):
    if uri.split('/')[3] == '2021' and uri.split('/')[4] >= '11':
        net_text = get_net_text_new(uri)
    else:
        net_text = get_net_text_old(uri)
    hash_text = get_hash_text(uri)
    parsed_data = {'ip': get_ips(net_text), 'domains': get_domains(net_text), 'hashes': get_hashes(hash_text)}
    return parsed_data
