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

DOMAIN = 'https://research.checkpoint.com'
SOURCE = __name__.split('.').pop()

scraper = cloudscraper.create_scraper()

hds = {
    "cookie": "_gcl_au=1.1.601166832.1745313001; _ga=GA1.1.1121295685.1745313001; _mkto_trk=id:750-DQH-528&token:_mch-checkpoint.com-38698cf678a8e15b9599070b9945fd1; sliguid=dc6354ca-7865-4d0a-9b02-69ee11f1f2bb; slirequested=true; _gd_visitor=73b04840-157b-403e-83db-3befe9f548b1; trd_cid=17453130034813949; trd_vid_l=2336%3A17453130034813949; trd_vuid_l=-8985871930332758600; OptanonAlertBoxClosed=2025-04-22T09:10:04.868Z; referralURL=; _an_uid=2606310944680970321; slireg=https://scout.eu1.salesloft.com; _gd_session=59eaeab7-fad7-4efd-8176-8ae024846ff7; _clck=k9dzcy%7C2%7Cfw1%7C0%7C1938; trd_ma_cookie=aWQ6NzUwLURRSC01MjgmdG9rZW46X21jaC1jaGVja3BvaW50LmNvbS0zODY5OGNmNjc4YThlMTViOTU5OTA3MGI5OTQ1ZmQx; _clsk=15mmkv2%7C1747631381917%7C5%7C1%7Ck.clarity.ms%2Fcollect; _uetsid=fc9842f033fb11f09ad4e152a6f232a5; _uetvid=925201801f5911f0acd9e12bf606f404; OptanonConsent=isGpcEnabled=0&datestamp=Mon+May+19+2025+13%3A09%3A47+GMT%2B0800+(%E5%8F%B0%E5%8C%97%E6%A8%99%E6%BA%96%E6%99%82%E9%96%93)&version=202301.1.0&isIABGlobal=false&hosts=&landingPath=NotLandingPage&groups=C0003%3A1%2CC0001%3A1%2CC0002%3A1%2CC0004%3A1&geolocation=TW%3BTPE&AwaitingReconsent=false; _ga_48VXKGDGCV=GS2.1.s1747630920$o4$g1$t1747631388$j51$l0$h0$dAR9OzVQzYYoeNXGNuwZr5R6cjOuxWsOb2A",
    "user-agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36"
}


def getResearch_checkpoint(url='', numPage=3):
    data = {}
    url = DOMAIN
    data['DOMAIN'] = DOMAIN
    data['source'] = SOURCE
    parseAllPagination(url, data, numPage)

def parseAllPagination(main_url, data, numPage): 
    pg_url = 'https://research.checkpoint.com/latest-publications/page/2/'
    parseList(pg_url, data)
    for pg in range(2, numPage+1):
        pg_url = 'https://research.checkpoint.com/latest-publications/page/' + str(pg) + '/'
        parseList(pg_url, data)

        

def parseList(pg_url, data):
    resp = requests.get(pg_url, headers=hds)
    doc = BeautifulSoup(resp.text, 'lxml')

    for news in doc.find_all('div', class_='display-flex desktop-view-socialshare'):
        # article url
        article_url = news.find('a')['href']
        data['url'] = article_url
        parseArticle(article_url, data)
        

def parseArticle(article_url, data):
    print("parseArticle", article_url)
    resp = requests.get(article_url, headers=hds)
    doc = BeautifulSoup(resp.text, 'lxml')

    #Hyper Links
    data['hyper_links'] = get_hyper_links(doc)
    
    #Title
    data['title'] = doc.find('h1', class_='h3').text.strip()

    # #DateTime February 24, 2025
    pattern = "%B %d, %Y"
    tm_str = doc.select('div.date')[0].text.strip()
    local_dt = datetime.strptime(tm_str, pattern)
    dt = timezone('Asia/Taipei').localize(local_dt)
    data['tm'] = int( (dt-datetime(1970, 1, 1, tzinfo=utc)).total_seconds() )


    #Content
    data['content'] = doc.find('div', class_='text border-bottom').text.strip()
    

    
    filterString(data)
    upsert_news_article(data)


