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

DOMAIN = 'https://www.trendmicro.com'
SOURCE = __name__.split('.').pop()


def getTrendmicro(url='', numPage=3):
    data = {}
    url = DOMAIN
    data['DOMAIN'] = DOMAIN
    data['source'] = SOURCE
    parseAllPagination(url, data, numPage)

def parseAllPagination(main_url, data, numPage): 
    pg_url = 'https://www.trendmicro.com/en_us/research.tagSearch.json'
    parseList(pg_url, data,retry=3)
        

def parseList(pg_url, data, retry):
    try:
        resp = requests.get(pg_url)
        doc = resp.json()
    except Exception as e:
        if retry == 0:
            print("Error:", e)
            return
        parseList(pg_url, data, retry-1)

    for news in doc['articles']:
        #article url
        article_url = news['path']
        data['url'] = article_url

        #Title
        data['title'] = news['title']

        #DateTime May 13, 2025
        pattern = "%b %d, %Y"
        tm_str = news['publishDate']
        local_dt = datetime.strptime(tm_str, pattern)
        dt = timezone('Asia/Taipei').localize(local_dt)
        data['tm'] = int( (dt-datetime(1970, 1, 1, tzinfo=utc)).total_seconds() )
        parseArticle(article_url, data,retry=3)
        

def parseArticle(article_url, data, retry):
    try:
        resp = requests.get(article_url)
        doc = BeautifulSoup(resp.text, 'lxml')
    except Exception as e:
        if retry == 0:
            print("Error:", e)
            return
        parseArticle(article_url, data, retry-1)

    #Hyper Links
    data['hyper_links'] = get_hyper_links(doc)
    

    #Content
    data['content'] = doc.select('article')[0].text.strip()
        
    
    filterString(data)
    upsert_news_article(data)
