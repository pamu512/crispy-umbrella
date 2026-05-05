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
import cloudscraper


DOMAIN = 'https://socket.dev'
SOURCE = __name__.split('.').pop()
scraper = cloudscraper.create_scraper()

def getSocket_dev(url='', numPage=3):
    data = {}
    url = DOMAIN
    data['DOMAIN'] = DOMAIN
    data['source'] = SOURCE
    parseAllPagination(url, data, numPage)

def parseAllPagination(main_url, data, numPage): 
    pg_url = DOMAIN + "/blog"
    parseList(pg_url, data)
        

def parseList(pg_url, data):
    resp = scraper.get(pg_url)
    doc = BeautifulSoup(resp.text, 'lxml')

    for news in doc.select('article a')[:100]:
        #article url
        article_url = DOMAIN + news['href']
        data['url'] = article_url
        #Title
        data['title'] = news.text.strip()
        
        parseArticle(article_url, data)

def parseArticle(article_url, data):
    resp = scraper.get(article_url)
    doc = BeautifulSoup(resp.text, 'lxml')


    #DateTime  April 23, 2025
    pattern = "%B %d, %Y"
    tm_str = doc.find('p', class_='css-0').text.strip()
    local_dt = datetime.strptime(tm_str, pattern)
    dt = timezone('Asia/Taipei').localize(local_dt)
    data['tm'] = int( (dt-datetime(1970, 1, 1, tzinfo=utc)).total_seconds() )
    
    #content
    data['content'] = doc.select('div.prose')[0].text
    

    #hyper_links
    data['hyper_links'] = get_hyper_links(doc)
    filterString(data)
    upsert_news_article(data)
