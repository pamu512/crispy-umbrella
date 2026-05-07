import re

with open('news/common/rule.txt',encoding='utf-8') as r:
    lines = [line.strip() for line in r]
PATTERN = '|'.join(lines)


def extract_iocs(content):
    # 正則表達式匹配常見的 IOC 格式（IP, URL, Hash）
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'  # 匹配 IPv4 地址
    url_pattern = r'https?://[^\s/$.?#].[^\s]*'  # 匹配 URL
    hash_pattern = r'\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b'  # 匹配 MD5, SHA1, SHA256 哈希

    iocs = []
    
    # 查找並提取 IOC
    iocs += re.findall(ip_pattern, content)
    iocs += re.findall(url_pattern, content)
    iocs += re.findall(hash_pattern, content)
    if iocs:
        return iocs
    else:
        return ''

def extract_mitre(text: str):
    """
    Get all MITRE ATT&CK Techc code:
      • TXXXX
      • TXXXX.XXX
    """
    pattern = r'T\d{4}(?:\.\d{3})?'   # The non-capturing group (?:...) ensures that the entire segment is returned by findall
    mitre_codes = re.findall(pattern, text)
    if mitre_codes:
        return mitre_codes
    else:
        return ""


def filterString(data):
    if 'raw_content' in data:
        content = data['raw_content']
    else:
        content = data['raw_content'] = data['content']

    data['content'] = re.sub(PATTERN, '', content, flags=re.MULTILINE)
    if 'author' in data:
        data['author'] = data['author'].strip()
    
    data['IOCs'] = extract_iocs(data['content'])
    data['MITRE'] = extract_mitre(data['content'])

def get_hyper_links(doc):
    hyper_links = []
    for link in doc.find_all('a', href=True):
        if 'ad.doubleclick.net' not in link['href']:
            if 'http' in str(link['href']):
                hyper_links.append(link['href'])

    return hyper_links