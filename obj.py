import inspect


class vuln_obj:
    def __init__(self):
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
        self.name=""
        self.url=""
        self.danger_level=""
        self.type=""
        self.cve=""
        self.cnvd=""
        self.find_time=""
        self.release_time=""
        self.update_time=""
        self.influence=""
        self.exp=""
        self.poc=""
        self.version=""
        self.description=""
        self.product=""
        self.ref=""
        self.origin=""


    # def insertrow(self):
    #     values = "'" + one[0] + "'"
    #     for i in range(1, len(one)):
    #         values = values + "," + "'" + one[i] + "'"
    #     sql = 'insert into cve_info values(' + values + ')'
    #     return

    def pr(self):
        vlist = [self.name, self.url, self.danger_level, self.type, self.cve, self.cnvd, self.find_time, self.release_time, self.update_time, self.influence, self.exp, self.poc, self.version, self.description, self.product, self.ref,self.origin]
        values = "'" + vlist[0] + "'"
        for i in range(1, len(vlist)):
            values = values + "," + "\"" + vlist[i] + "\""
        sql = 'insert into vul_info values(' + values + ');'
        return sql