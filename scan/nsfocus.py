import datetime
import re

from bs4 import BeautifulSoup
# -*- coding:utf-8 -*-

import requests

from obj import vuln_obj


async def scan(day=1):
    pageNo=1
    today = datetime.date.today()  # 获取当前日期
    delta = datetime.timedelta(days=day)  # 创建一个timedelta对象，表示7天
    now_date = today - delta  # 计算前7天的日期

    baseurl = "http://www.nsfocus.net/"
    quit_flag=False

    nsfocus_details = []
    while True:
        url = "http://www.nsfocus.net/index.php?act=sec_bug&type_id=&os=&keyword=&page="+str(pageNo)
        try:
            r = requests.get(url,timeout=30)
        except Exception as e:
            print('连接超时。。。' + str(e))

        html = BeautifulSoup(r.text, 'html.parser')
        links=list()
        vul_list = html.find_all(class_='vul_list')
        for vul in vul_list:
            links.extend(vul.find_all('a'))

        for link in links:
            obj = getURLDATA(baseurl + link.attrs['href'])
            date_time = datetime.datetime.strptime(obj.update_time,'%Y-%m-%d').date()
            if date_time<now_date:
                quit_flag = True
                break

            nsfocus_details.append(obj)


        if quit_flag:
            return nsfocus_details

        pageNo+=1




"""
漏洞名字
url
危险等级:['高','中','低']
漏洞类型
cve
cnnvd
发现时间:"2020-01-01"
报告时间
更新时间
影响范围:['广','一般','小']
是否存在exp[1,0]
是否存在poc[1,0]
影响版本
漏洞描述
影响产品
引用
来源
"""
def getURLDATA(url):
    re_date = re.compile(r"20\d{2}-\d{2}-\d{2}")

    obj = vuln_obj()

    header = {
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.80 Safari/537.36',
        'Connection': 'keep-alive', }
    r = requests.get(url, headers=header, timeout=30)
    r.encoding = 'utf-8'
    html = BeautifulSoup(r.text, 'html.parser')
    vulbar = html.find(class_='vulbar')
    obj.name=(vulbar.find('div').find('b').text)
    obj.url = url
    obj.danger_level=''
    obj.type=''
    obj.cve = vulbar.find('a',attrs={'target':'_blank'}).text
    obj.cnvd = ''
    try:
        obj.find_time = re_date.findall(str(vulbar))[0]
        obj.release_time = re_date.findall(str(vulbar))[0]
        obj.update_time = re_date.findall(str(vulbar))[1]
    except:
        obj.find_time = "2000-01-01"
        obj.release_time = "2000-01-01"
        obj.update_time = "2000-01-01"
    obj.influence= ""
    obj.exp=""
    obj.poc=""
    version = str(vulbar.find('blockquote').text.replace('<br>','\n').replace('</br>',''))
    if "\n" in version or '<' in version or '>'in version  or '=' in version :
        obj.version = version
        obj.product = version.split('\n')[0]
    else:
        obj.version = ''
        obj.product = version

    re_description = re.compile(r""+obj.cve+"</a>(.*?)<b>\u5EFA\u8BAE",re.DOTALL)
    # print(str(vulbar))
    obj.description = str(re_description.findall(str(vulbar))[0]).replace('\n','').replace('<br>','\n').replace('</br>','').replace('<br/>','')
    obj.product=''
    obj.ref=''
    obj.origin='nsfocus'
    return obj




