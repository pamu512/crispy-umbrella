#news/bleepingcomputer.py
#!/usr/bin/env python
# -*- coding: utf-8 -*-

from bs4 import BeautifulSoup
from datetime import datetime
from pytz import timezone,utc
from .common.sqlite_store import upsert_news_article
import stealth_requests as requests
from .common.parser import filterString, get_hyper_links

DOMAIN = 'https://www.elastic.co'
SOURCE = __name__.split('.').pop()

def getElastic_security_labs(url='', numPage=3):
    data = {}
    url = DOMAIN
    data['DOMAIN'] = DOMAIN
    data['source'] = SOURCE
    parseAllPagination(url, data, numPage)

def parseAllPagination(main_url, data, numPage): 
    topics = ['campaigns', 'detection-science', 'generative-ai', 'groups-and-tactics', 'malware-analysis', 'perspectives', 'security-research']
    for pg in topics:
        pg_url = DOMAIN + "/security-labs/topics/" + str(pg) + "/"
        parseList(pg_url, data)
        

def parseList(pg_url, data):
    resp = requests.get(pg_url)
    doc = BeautifulSoup(resp.text, 'lxml')

    #handle the first article differently
    first_news = doc.select('div.flex.flex-col.justify-between.max-w-xl.lg\:mt-0.mt-10.pr-10 a')[0]
    #article url
    article_url = DOMAIN + first_news['href']
    data['url'] = article_url
    #Title
    data['title'] = first_news.text.strip()
    parseArticle(article_url, data, 0)

    for news in doc.select('div.grid.sm\:grid-cols-2.lg\:grid-cols-4.gap-8 a'):
        #article url
        article_url = DOMAIN + news['href']
        data['url'] = article_url
        #Title
        data['title'] = news.select('h3')[0].text.strip()

        parseArticle(article_url, data, 0)

def parseArticle(article_url, data, retry_times):
    resp = requests.get(article_url)
    doc = BeautifulSoup(resp.text, 'lxml')
    
    #DateTime  25 June 2025
    pattern = "%d %B %Y"
    tm_str = doc.select('time.block.mb-2.md\:mb-0.md\:inline-block.article-published-date')[0].text.strip()  
    local_dt = datetime.strptime(tm_str, pattern)
    dt = timezone('Asia/Taipei').localize(local_dt)
    data['tm'] = int( (dt-datetime(1970, 1, 1, tzinfo=utc)).total_seconds() )

    #Content
    content_html = doc.find('div', class_='prose lg:prose-lg prose-invert w-full article-content')
    data['content'] = ''
    for p in content_html.find_all('p'):
        data['content'] = data['content'] + p.get_text() + '\n'
    data['hyper_links'] = get_hyper_links(doc)
    filterString(data)
    upsert_news_article(data)
