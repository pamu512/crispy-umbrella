#news/bleepingcomputer.py
#!/usr/bin/env python
# -*- coding: utf-8 -*-

from bs4 import BeautifulSoup
from datetime import datetime
from pytz import timezone,utc
from .common.sqlite_store import upsert_news_article
import stealth_requests as requests
from .common.parser import filterString, get_hyper_links

DOMAIN = 'https://blog.talosintelligence.com'
SOURCE = __name__.split('.').pop()

def getTalosintelligence(url='', numPage=3):
    data = {}
    url = DOMAIN
    data['DOMAIN'] = DOMAIN
    data['source'] = SOURCE
    parseAllPagination(url, data, numPage)

def parseAllPagination(main_url, data, numPage): 
    for pg in range(1, numPage+1):
        pg_url = DOMAIN + "/page/" + str(pg) + "/"
        parseList(pg_url, data)
        

def parseList(pg_url, data):
    resp = requests.get(pg_url)
    doc = BeautifulSoup(resp.text, 'lxml')

    # Check if the URL ends with '1' to handle the first page differently
    if pg_url.rstrip('/').endswith('1'):
        first_news = doc.select('div.container.pe-3 h2 a')[0]
        #article url
        article_url = DOMAIN + first_news['href']
        data['url'] = article_url
        #Title
        data['title'] = first_news.text.strip()
        parseArticle(article_url, data, 0)

    for news in doc.select('div.container.p-4.pb-5 h2 a'):
        #article url
        article_url = DOMAIN + news['href']
        data['url'] = article_url
        #Title
        data['title'] = news.text.strip()

        parseArticle(article_url, data, 0)


def parseArticle(article_url, data, retry_times):
    resp = requests.get(article_url)
    doc = BeautifulSoup(resp.text, 'lxml')
    
    # DateTime  December 26, 2024
    pattern = "%B %d, %Y"
    tm_str = doc.select('time.post-datetime')[0].text.strip()
    # Example tm_str: "Wednesday, July 2, 2025 06:00"
    # We want to extract "July 2, 2025"
    parts = tm_str.split(',')
    if len(parts) >= 3:
        # parts[1] is " July 2", parts[2] is " 2025 06:00"
        date_part = parts[1].strip() + ', ' + parts[2].strip().split()[0]  # "July 2, 2025"
    else:
        date_part = tm_str  # fallback
    local_dt = datetime.strptime(date_part, pattern)
    dt = timezone('Asia/Taipei').localize(local_dt)
    data['tm'] = int( (dt-datetime(1970, 1, 1, tzinfo=utc)).total_seconds() )

    #Content
    content_html = doc.find('div', class_='post-content')
    data['content'] = ''
    for p in content_html.find_all('p'):
        data['content'] = data['content'] + p.get_text() + '\n'
    data['hyper_links'] = get_hyper_links(doc)
    filterString(data)
    upsert_news_article(data)
