#news/bleepingcomputer.py
#!/usr/bin/env python
# -*- coding: utf-8 -*-

from bs4 import BeautifulSoup
from datetime import datetime
from pytz import timezone,utc
from .common.sqlite_store import upsert_news_article
import stealth_requests as requests
from .common.parser import filterString, get_hyper_links

DOMAIN = 'https://cyberscoop.com/news/threats'
SOURCE = __name__.split('.').pop()

def getCyberscoop(url='', numPage=3):
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
    for news in doc.select('div.zox-art-title a'):
        #article url
        article_url = news['href']
        data['url'] = article_url
        #Title
        data['title'] = news.select('h2')[0].text.strip()

        parseArticle(article_url, data, 0)

def parseArticle(article_url, data, retry_times):
    resp = requests.get(article_url)
    doc = BeautifulSoup(resp.text, 'lxml')
    
    #DateTime  December 26, 2024
    pattern = "%B %d, %Y"
    tm_str = doc.select('time.post-date.updated')[0].text.strip()
    # Extract only the date part (remove the time in parentheses)
    date_part = tm_str.split(' (')[0]  # Splits on ' (' and takes the first part
    local_dt = datetime.strptime(date_part, pattern)
    dt = timezone('Asia/Taipei').localize(local_dt)
    data['tm'] = int( (dt-datetime(1970, 1, 1, tzinfo=utc)).total_seconds() )

    #Content
    content_html = doc.find('div', class_='zox-post-body left zoxrel zox100')
    data['content'] = ''
    for p in content_html.find_all('p'):
        data['content'] = data['content'] + p.get_text() + '\n'
    data['hyper_links'] = get_hyper_links(doc)
    filterString(data)
    upsert_news_article(data)
