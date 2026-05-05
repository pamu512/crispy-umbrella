#news/bleepingcomputer.py
#!/usr/bin/env python
# -*- coding: utf-8 -*-

from bs4 import BeautifulSoup
from datetime import datetime
from pytz import timezone,utc
from .common.sqlite_store import upsert_news_article
import requests
from .common.parser import filterString, get_hyper_links




DOMAIN = 'https://cloud.google.com'
SOURCE = __name__.split('.').pop()

def getGooglecloud_threat_intelligence(url='', numPage=3):
    data = {}
    url = 'https://feeds.feedburner.com/threatintelligence/pvexyqv7v0v'
    data['DOMAIN'] = DOMAIN
    data['source'] = SOURCE
    parseAllPagination(url, data, numPage)

def parseAllPagination(main_url, data, numPage): 
    parseList(main_url, data)
    
        

def parseList(pg_url, data):
    resp = requests.get(pg_url)
    doc = BeautifulSoup(resp.text, 'xml')
    for news in doc.select('item'):
        #title
        data['title'] = news.select('title')[0].text.strip()
        #URL
        article_url = news.select('link')[0].text.strip()
        data['url'] = article_url
        #DateTime Mon, 10 Mar 2025 14:00:00 +0000
        pattern = "%a, %d %b %Y %H:%M:%S %z"
        pub = news.find("pubDate")
        tm_str = pub.text.strip() if pub else ""
        local_dt = datetime.strptime(tm_str, pattern)
        naive_dt = local_dt.replace(tzinfo=None)
        localized_dt = timezone('Asia/Taipei').localize(naive_dt)
        data['tm'] = int((localized_dt - datetime(1970, 1, 1, tzinfo=utc)).total_seconds())
        #content
        description = news.select('description')[0].text.strip()
        content = BeautifulSoup(description, 'lxml')
        data['content'] = content.text.strip()
        data['hyper_links'] = get_hyper_links(doc)
        parseArticle(article_url, data)
    

def parseArticle(article_url, data):
    filterString(data)
    upsert_news_article(data)
