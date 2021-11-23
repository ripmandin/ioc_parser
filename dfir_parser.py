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


urls = ['https://thedfirreport.com/2020/04/30/tricky-pyxie/',
        'https://thedfirreport.com/2021/06/03/weblogic-rce-leads-to-xmrig/',
        'https://thedfirreport.com/2021/01/11/trickbot-still-alive-and-well/',
        "https://thedfirreport.com/2021/06/28/hancitor-continues-to-push-cobalt-strike/",
        "https://thedfirreport.com/2021/11/01/from-zero-to-domain-admin/",
        "https://thedfirreport.com/2021/03/29/sodinokibi-aka-revil-ransomware/",
        "https://thedfirreport.com/2021/05/02/trickbot-brief-creds-and-beacons/",
        "https://thedfirreport.com/2021/11/15/exchange-exploit-leads-to-domain-wide-ransomware/"]
# print(parse(urls[0]))
#

#
# correct_ips = [["45.86.163.78", "195.189.99.74", "206.189.10.247", "161.35.109.168"],
#                ['102.68.17.97', '103.76.150.14', '103.9.188.23', '109.185.139.90', '138.185.72.142', '147.135.78.200', '148.216.32.55', '172.82.179.170', '173.81.4.147', '182.253.184.130', '185.205.250.162', '190.122.168.219', '196.41.57.46', '200.90.11.177', '202.166.211.197', '23.108.57.39', '31.134.124.90', '31.211.85.110', '41.77.134.250', '5.59.205.32', '62.213.14.166', '77.95.93.132', '78.138.187.231', '81.95.45.234', '84.21.206.164', '85.112.74.178', '87.116.151.237', '87.76.1.81', '89.250.208.42', '91.185.236.170', '91.225.231.120', '96.9.77.142'],
#                ['148.251.71.182', '18.221.115.241', '198.144.189.74', '217.23.5.42', '37.139.3.208', '86.57.38.156']]
#
# correct_domains = [["smalleststores.com", "cloudmetric.online", "cikawemoret34.space", "nomovee.website"],
#                    ["wideri.com", "http://172.82.179.170/w.dll"],
#                    ["tcp.symantecserver.co"]]

#
n = 0
if urls[n].split('/')[3] == '2021' and urls[n].split('/')[4] >= '11':
    text = get_net_text_new(urls[n])
else:
    text = get_net_text_old(urls[n])
#print(text)
ip0 = get_ips(text)
print("ip0", ip0)
#ipc = correct_ips[n]
#print("ipc", ipc)
print(get_domains(text))
# #print(correct_domains[n])
#print(get_hash_text(urls[n]))
print(get_hashes(get_hash_text(urls[n])))

#TEST

# for i, n in enumerate(urls):
#     if n.split('/')[3] == '2021' and int(n.split('/')[4])>=11:
#         text = get_page_data_new(n)
#     else:
#         text = get_page_data_old(n)
#     #print(text)
#     print(len(get_ips(text)), get_ips(text))
#     print(len(correct_ips[i]), correct_ips[i])
#     print(len(get_domains(text)), get_domains(text))
#     print(len(correct_domains[i]), correct_domains[i])