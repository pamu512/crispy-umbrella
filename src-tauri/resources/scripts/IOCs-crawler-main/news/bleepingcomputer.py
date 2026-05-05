#news/bleepingcomputer.py
#!/usr/bin/env python
# -*- coding: utf-8 -*-

from bs4 import BeautifulSoup
from datetime import datetime
from pytz import timezone,utc
from .common.sqlite_store import upsert_news_article
import requests
from .common.parser import filterString, get_hyper_links

DOMAIN = 'https://www.bleepingcomputer.com'
SOURCE = __name__.split('.').pop()

hds = {
    'cookie':'cf_clearance=vs1nB13p9oISFvd3YMh8F3qSK0wqhnaI5eVgYmyz4.I-1740144837-1.2.1.1-ziiCYS1lo0ysXYT7llJHqloBFFDylSgA1GL36v49TkzQkF2byPmFhPVX5iQjVeUru2BkKDjaWVx00bDfCy.B4MGXIA6jNtQ5La08dYvx6CIUjGhoqOVT9iKWqzWXkZylKE6fcZW01wQaUxGfhdmByyauOnPVfbIxYOFCLoMVC7pKjIOBIV1GggPqMwsaKY6Qdew_iwhGNArdqoW_LBhGhstSwp7Pzf0mAC1dQJzrPYZbPos_p6FmQ1CyjuuD_2j5ctb2uA0pg4nYmd1HaSQtWkV6upspJDjGn5bSrlbeCc1a9MR_413U1jh17f81nsu2zFq5SwOBH4i_dgyFY3T.qw',
    'user-agent':'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36',
}

def getBleeping_computer(url='', numPage=3):
    data = {}
    url = DOMAIN
    data['DOMAIN'] = DOMAIN
    data['source'] = SOURCE
    parseAllPagination(url, data, numPage)

def parseAllPagination(main_url, data, numPage): 
    parseList(main_url, data)
    for pg in range(2, numPage+1):
        pg_url = DOMAIN + "/page/" + str(pg) + "/"
        parseList(pg_url, data)
        

def parseList(pg_url, data):
    resp = requests.get(pg_url, headers=hds)
    doc = BeautifulSoup(resp.text, 'lxml')
    for news in doc.select('#bc-home-news-main-wrap li div.bc_latest_news_text'):
        #article url
        article_url = news.select('h4 a')[0]['href']
        if DOMAIN in article_url:
            data['url'] = article_url
            #Title
            data['title'] = news.select('h4 a')[0].text.strip()
            #DateTime March 10, 2025
            pattern = "%B %d, %Y"
            tm_str = doc.select('.bc_news_date')[0].text.strip()
            local_dt = datetime.strptime(tm_str, pattern)
            dt = timezone('Asia/Taipei').localize(local_dt)
            data['tm'] = int( (dt-datetime(1970, 1, 1, tzinfo=utc)).total_seconds() )
            parseArticle(article_url, data, 0)

def parseArticle(article_url, data, retry_times):
    resp = requests.get(article_url, headers=hds)
    doc = BeautifulSoup(resp.text, 'lxml')
    
    #Content
    if not doc.select('.articleBody') and retry_times < 3:
        parseArticle(article_url, data, retry_times+1)
        return
    if doc.select('.articleBody'):
        data['content'] = doc.select('.articleBody')[0].text.strip()
        data['hyper_links'] = get_hyper_links(doc)
        filterString(data)
        upsert_news_article(data)
