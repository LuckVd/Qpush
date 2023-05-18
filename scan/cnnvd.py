import datetime
import logging
import re

import requests as requests
from bs4 import BeautifulSoup

from obj import vuln_obj
from sql_helper import is_not_exist, insertTo


async def scan(day=1):
    pageNo=1
    today = datetime.date.today()  # 获取当前日期
    delta = datetime.timedelta(days=day)  # 创建一个timedelta对象，表示7天
    now_date = today - delta  # 计算前7天的日期

    cnnvd_details = []

    while True:
        url = 'http://123.124.177.30/web/vulnerability/querylist.tag?pageno=' + str(pageNo) + '&repairLd='
        header = {
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.80 Safari/537.36',
            'Connection': 'keep-alive',
        }
        try:
            r = requests.get(url, headers=header, timeout=30)
        except Exception as e:
            print('连接超时。。。' + str(e))
            break

        html = BeautifulSoup(r.text, 'html.parser')
        links = html.find_all(class_='a_title2')
        for link in links:
            try:
                k = str(link.attrs['href'])
                one = getURLDATA("http://123.124.177.30" + k)  # 获取每一个单独漏洞的详细信息页面one = getURLDATA("http://123.124.177.30" + k)  # 获取每一个单独漏洞的详细信息页面
                cnnvd_details.append(one)
                # print(one)
            except Exception as e:
                print("http://123.124.177.30" + k)
                break
        pageNo+=1
        if one[6]<=str(now_date):
            break

    return  cnnvd_details




"""
0:漏洞名称
1:漏洞在CNNVD上的链接
2:漏洞在CNNVD上的编号
3:危害等级
4:CVE编号
5:漏洞类型
6:发布时间
7:威胁类型
8:更新时间
9:厂商
10:漏洞简介
"""
def getURLDATA(url):
    obj = vuln_obj()

    header = {
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.80 Safari/537.36',
        'Connection': 'keep-alive', }
    r = requests.get(url, headers=header, timeout=30)
    html = BeautifulSoup(r.text, 'html.parser')
    link = html.find(class_='detail_xq w770')  # 漏洞信息详情
    vuln_name = link.find('h2').text.lstrip().rstrip() #漏洞名称
    vuln_num = re.findall(r'CNNVD-+\d+-+\d+',str(url))[0] #漏洞编号
    link_introduce = html.find(class_='d_ldjj')  # 漏洞简介
    link_others = html.find_all(class_='d_ldjj m_t_20')  # 其他
    one_cve_info = []
    #漏洞名称
    try:
        obj.name=str(vuln_name)
        one_cve_info.append(str(vuln_name))
    except:
        one_cve_info.append("")
    #漏洞在CNNVD上的链接
    try:
        one_cve_info.append(str(url))
    except:
        one_cve_info.append("")
    #漏洞在CNNVD上的编号
    try:
        one_cve_info.append(vuln_num)
    except:
        one_cve_info.append("")
    # 危害等级
    try:

        one_cve_info.append(str(link.contents[3].contents[5].find('a').text.lstrip().rstrip()))
    except:
        #print("危害等级:is empty")
        one_cve_info.append("")
    #CVE编号
    try:
        one_cve_info.append(str(link.contents[3].contents[7].find('a').text.lstrip().rstrip()))
    except:
        #print("CVE编号:is empty")
        one_cve_info.append("")
    #漏洞类型
    try:
        one_cve_info.append(str(link.contents[3].contents[9].find('a').text.lstrip().rstrip()))

    except:
        #print("漏洞类型:is empty")
        one_cve_info.append("")

    #发布时间
    try:
        one_cve_info.append(str(link.contents[3].contents[11].find('a').text.lstrip().rstrip()))
    except:
       # print("发布时间:is empty")
        one_cve_info.append("")
    #威胁类型
    try:
        one_cve_info.append(str(link.contents[3].contents[13].find('a').text.lstrip().rstrip()))
    except:
        #print("威胁类型:is empty")
        one_cve_info.append("")

    #更新时间
    try:
        one_cve_info.append(str(link.contents[3].contents[15].find('a').text.lstrip().rstrip()))
    except:
        #print("更新时间:is empty")
        one_cve_info.append("")
    #厂商
    try:
        one_cve_info.append(str(link.contents[3].contents[17].find('a').text.lstrip().rstrip()))
    except:
        #print("厂商:is empty")
        one_cve_info.append("")

    #漏洞简介
    try:
        link_introduce_data = BeautifulSoup(link_introduce.decode(), 'html.parser').find_all(name='p')
        s = ""
        for i in range(0, len(link_introduce_data)):
            s = s + str(link_introduce_data[i].text.lstrip().rstrip())
        one_cve_info.append(s)
    except:
        one_cve_info.append("")

    if (len(link_others) != 0):
        try:
            # 漏洞公告
            link_others_data1 = BeautifulSoup(link_others[0].decode(), 'html.parser').find_all(name='p')
            s = ""
            for i in range(0, len(link_others_data1)):
                s = s + str(link_others_data1[i].text.lstrip().rstrip())
            one_cve_info.append(s)
        except:
            one_cve_info.append("")

        try:
            # 参考网址
            link_others_data2 = BeautifulSoup(link_others[1].decode(), 'html.parser').find_all(name='p')
            s = ""
            for i in range(0, len(link_others_data2)):
                s = s + str(link_others_data2[i].text.lstrip().rstrip())

            one_cve_info.append(s)
        except:
            one_cve_info.append("")

        try:
            # 受影响实体
            link_others_data3 = BeautifulSoup(link_others[2].decode(), 'html.parser').find_all('a', attrs={
                'class': 'a_title2'})
            s = ""
            for i in range(0, len(link_others_data3)):
                s = s + str(link_others_data3[i].text.lstrip().rstrip())

            one_cve_info.append(s)
        except:
            one_cve_info.append("")

        try:
            # 补丁
            link_others_data3 = BeautifulSoup(link_others[3].decode(), 'html.parser').find_all('a', attrs={
                'class': 'a_title2'})
            s = ""
            for i in range(0, len(link_others_data3)):
                s = s + str(link_others_data3[i].text.lstrip().rstrip())

            one_cve_info.append(s)
        except:
            one_cve_info.append("")
    else:
        one_cve_info.append("")
        one_cve_info.append("")
        one_cve_info.append("")
        one_cve_info.append("")
    return one_cve_info
