#https://www.oscs1024.com/oscs/v1/intelligence/list
#{"page":1,"per_page":10}
import datetime
import json
import logging
import time

import requests

from obj import vuln_obj


async def scan(day=1):
    today = datetime.date.today()  # 获取当前日期
    delta = datetime.timedelta(days=day)  # 创建一个timedelta对象，表示7天
    now_date = today - delta  # 计算前7天的日期
    quit_flag=False

    cnnvd_details = []

    while True:
        url = 'https://www.oscs1024.com/oscs/v1/intelligence/list'
        header = {
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.80 Safari/537.36',
            'Connection': 'keep-alive',
        }
        data={"page":1,"per_page":10}
        try:
            r = requests.post(url, headers=header, data=data,timeout=300)
        except Exception as e:
            print('连接超时。。。' + str(e))
            break
        datalist=[]
        try:
            json_response = json.loads(r.text)
            datalist = json_response['data']['data']

        except Exception as e:
            logging.log(logging.ERROR,str(e))

        for data in datalist:
            dt = datetime.datetime.strptime(data['public_time'][:data['public_time'].rfind('+')], '%Y-%m-%dT%H:%M:%S')
            date_time = datetime.datetime.strptime(dt.strftime('%Y-%m-%d'), '%Y-%m-%d').date()
            if date_time <=now_date:
                quit_flag = True
                break
            obj = get_OSCS_DATA(data)
            cnnvd_details.append(obj)
        if quit_flag:
            return cnnvd_details



def get_OSCS_DATA(data):
    url = "https://www.oscs1024.com/oscs/v1/vdb/info"
    data1 = {"vuln_no":data['mps']}
    datastr = str(data1)
    datastr=datastr.strip().replace(' ','')
    header = {
        'user-agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.80 Safari/537.36',
        'Connection':'keep-alive',
        'Content-Type':'application/json'
    }

    try:
        obj = vuln_obj()
        r = requests.post(url, headers=header, data=json.dumps(data1,separators=(',',":")), timeout=30)
        resp_json = json.loads(r.text)
        obj.name = resp_json['data'][0]['vuln_title']
        obj.url = "https://www.oscs1024.com/hd/"+data['mps']
        obj.danger_level = data['level']
        obj.type = resp_json['data'][0]['vuln_type']
        obj.cve = resp_json['data'][0]['cve_id']
        obj.cnvd = resp_json['data'][0]['cnvd_id']
        obj.find_time = str(datetime.datetime.strptime(data['created_at'][:data['created_at'].rfind('+')], '%Y-%m-%dT%H:%M:%S'))
        obj.release_time = str(datetime.datetime.strptime(data['public_time'][:data['public_time'].rfind('+')], '%Y-%m-%dT%H:%M:%S'))
        obj.update_time = str(datetime.datetime.strptime(data['updated_at'][:data['updated_at'].rfind('+')], '%Y-%m-%dT%H:%M:%S'))
        # obj.find_time = str(datetime.datetime.fromisoformat(data['created_at']).date())
        # obj.release_time = str(datetime.datetime.fromisoformat(data['public_time']).date())
        # obj.update_time = str(datetime.datetime.fromisoformat(data['updated_at']).date())
        obj.influence = resp_json['data'][0]['scope_influence']
        obj.exp = str(data['is_exp'])
        obj.poc = str(data['is_poc'])
        obj.version = str([i['affected_version'] for i in resp_json['data'][0]['effect']])
        obj.description = str(resp_json['data'][0]['description'])
        obj.product=""
        obj.ref = str(resp_json['data'][0]['references'])
        obj.origin = "oscs"
        return obj
    except Exception as e:
        logging.log(logging.ERROR,'连接超时。。。' + str(e))
        return None
