# This is a sample Python script.
# -*- coding:utf-8 -*-
import asyncio
import logging
from obj import vuln_obj
from scan.cnnvd import scan as cnnvd_scan
from scan.oscs import scan as oscs_scan
from scan.exploit_db import scan as exploit_scan
from scan.nsfocus import scan as nsf_scan
from sql_helper import is_not_exist, insertTo, insertall

# 设置日志级别为DEBUG
logging.basicConfig(level=logging.DEBUG)

# 创建日志记录器
logger = logging.getLogger(__name__)

# 创建控制台处理器
console_handler = logging.StreamHandler()

# 将控制台处理器添加到日志记录器中
logger.addHandler(console_handler)



async def async_run():
    tasks = []
    tasks.append(exploit_scan(7))
    tasks.append(oscs_scan(7))
    tasks.append(nsf_scan(7))
    results_list = await asyncio.gather(*tasks)
    # print(results_list)

    # for one in results[0]:
    #     if is_not_exist(one):
    #         logging.log(logging.INFO, one[2] + ":" + one[0] + ":" + one[6])
    #         insertTo(one)
    insertall(results_list)
def main():
    loop = asyncio.get_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(async_run())


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    main()

# See PyCharm help at https://www.jetbrains.com/help/pycharm/
