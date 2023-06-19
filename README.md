# Qpush
一个python脚本，获取近期漏洞信息

在运行爬虫前先运行installDb.py创建数据库

在main.py中调用插件爬取各个网站的漏洞信息，插件只接受一个int参数n，表示最多爬取n天之前的漏洞信息。
在插入数据库时，漏洞根据cve编号，cnvd编号，name进行了去重


![image](https://github.com/LuckVd/Qpush/assets/37114923/8df5126e-14aa-4633-a0d7-3d932c7c846c)
