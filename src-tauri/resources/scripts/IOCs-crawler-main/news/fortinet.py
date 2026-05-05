#news/bleepingcomputer.py
#!/usr/bin/env python
# -*- coding: utf-8 -*-

from bs4 import BeautifulSoup
from datetime import datetime
from pytz import timezone,utc
from .common.sqlite_store import upsert_news_article
import requests
from .common.parser import filterString, get_hyper_links
import re

DOMAIN = 'https://www.fortinet.com'
SOURCE = __name__.split('.').pop()


def getFortinet(url='', numPage=3):
    data = {}
    url = DOMAIN
    data['DOMAIN'] = DOMAIN
    data['source'] = SOURCE
    parseAllPagination(url, data, numPage)

def parseAllPagination(main_url, data, numPage): 
    parseList(main_url, data)
    for pg in range(1, numPage+1):
        pg_url = DOMAIN + "/content/fortinet-blog/us/en/threat-research/jcr:content/root/bloglist."+ str(pg) +".html"
        parseList(pg_url, data)
        

def parseList(pg_url, data):
    resp = requests.get(pg_url)
    doc = BeautifulSoup(resp.text, 'lxml')
    for news in doc.select('h2.b3-blog-list__title a'):
        #article url
        article_url = DOMAIN + news['href']
        data['url'] = article_url
        #Title
        data['title'] = news.text.strip()
        
        parseArticle(article_url, data)

def parseArticle(article_url, data):
    resp = requests.get(article_url)
    doc = BeautifulSoup(resp.text, 'lxml')


    #DateTime  | December 26, 2024
    pattern = "| %B %d, %Y"
    tm_str = doc.select('span.b15-blog-meta__date')[0].text.strip()
    local_dt = datetime.strptime(tm_str, pattern)
    dt = timezone('Asia/Taipei').localize(local_dt)
    data['tm'] = int( (dt-datetime(1970, 1, 1, tzinfo=utc)).total_seconds() )

    #Content
    print("article_url:",article_url)
    if doc.select('div.b3-blog-list__row'):
        content_html = str(doc.select('div.b3-blog-list__row')[0])
        data['content'] = doc.select('div.b3-blog-list__row')[0].text.strip()
    else:
        content_html = doc.find('div', class_='cmp cmp-text aem-GridColumn aem-GridColumn--default--12')
        data['content'] = ''
        for p in content_html.find_all('p'):
            data['content'] = data['content'] + p.get_text() + '\n'
    data['hyper_links'] = get_hyper_links(doc)
    filterString(data)
    upsert_news_article(data)
