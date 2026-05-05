#news/bleepingcomputer.py
#!/usr/bin/env python
# -*- coding: utf-8 -*-

from bs4 import BeautifulSoup
from datetime import datetime
from pytz import timezone,utc
from .common.sqlite_store import upsert_news_article
import requests
from .common.parser import filterString, get_hyper_links
import cloudscraper


scraper = cloudscraper.create_scraper()

DOMAIN = 'https://thehackernews.com'
SOURCE = __name__.split('.').pop()

def getThehackernews(url='', numPage=3):
    data = {}
    url = DOMAIN
    data['DOMAIN'] = DOMAIN
    data['source'] = SOURCE
    parseAllPagination(url, data, numPage)

def parseAllPagination(main_url, data, numPage): 
    parseList(main_url, data, numPage)
    
        

def parseList(pg_url, data, numPage):
    resp = scraper.get(pg_url)
    doc = BeautifulSoup(resp.text, 'lxml')
    if numPage > 0:
        next_page_url = doc.select('a.blog-pager-older-link-mobile')[0]['href']
        parseList(next_page_url, data, numPage-1)

    for news in doc.select('a.story-link'):
        article_url = news['href']
        if DOMAIN in article_url:
            data['url'] = article_url
            parseArticle(article_url, data, 0)
    

def parseArticle(article_url, data, retry_times):
    resp = scraper.get(article_url)
    doc = BeautifulSoup(resp.text, 'lxml')
    #Title
    if doc.select('.story-title'):
        data['title'] = doc.select('.story-title')[0].text.strip()
    else:
        print('fliaed to get title',article_url)
        return
    #DateTime 2025-03-10T15:16:00+05:30
    pattern = "%Y-%m-%dT%H:%M:%S%z"
    tm_str = doc.find('meta', {'itemprop': 'datePublished'})['content']
    local_dt = datetime.strptime(tm_str, pattern)
    naive_dt = local_dt.replace(tzinfo=None)
    localized_dt = timezone('Asia/Taipei').localize(naive_dt)
    data['tm'] = int((localized_dt - datetime(1970, 1, 1, tzinfo=utc)).total_seconds())

    #Content
    data['content'] = doc.select('div.post-body div#articlebody')[0].text.strip()
    data['hyper_links'] = get_hyper_links(doc)
    
    filterString(data)
    upsert_news_article(data)
