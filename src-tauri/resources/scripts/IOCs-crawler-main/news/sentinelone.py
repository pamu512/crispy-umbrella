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

DOMAIN = 'https://www.sentinelone.com'
SOURCE = __name__.split('.').pop()


def getSentinelone(url='', numPage=3):
    data = {}
    url = DOMAIN
    data['DOMAIN'] = DOMAIN
    data['source'] = SOURCE
    parseAllPagination(url, data, numPage)

def parseAllPagination(main_url, data, numPage): 
    for pg in range(1, numPage+1):
        pg_url = DOMAIN + "/blog/page/"+ str(pg) +"/"
        parseList(pg_url, data)

        

def parseList(pg_url, data):
    resp = requests.get(pg_url)
    doc = BeautifulSoup(resp.text, 'lxml')

    for news in doc.select('article a'):
        #article url
        article_url = news['href']
        data['url'] = article_url
        
        parseArticle(article_url, data)


def parseArticle(article_url, data):
    resp = requests.get(article_url)
    doc = BeautifulSoup(resp.text, 'lxml')
    #Hyper Links
    data['hyper_links'] = get_hyper_links(doc)

    #Title
    data['title'] = doc.select('h1.entry-title')[0].text.strip()
    
    #DateTime April 24, 2025
    pattern = "%B %d, %Y"
    tm_str = doc.select('div.post-meta time')[0].text.strip()
    local_dt = datetime.strptime(tm_str, pattern)
    dt = timezone('Asia/Taipei').localize(local_dt)
    data['tm'] = int( (dt-datetime(1970, 1, 1, tzinfo=utc)).total_seconds() )

    #Content
    data['content'] = doc.select('article div.entry-content')[0].text.strip()

        
    
    filterString(data)
    upsert_news_article(data)
