from lib.user import NginxVisitor
import re
from config import *
import time

class LogParser:
    def __init__(self, log_path, regex):
        # 同一ip的访问请求，那么就是list中存放dic
        self.path = log_path
        self.regex = regex
        self.content = self.ini_file()
        self.visitor = []
        self.ipList = {}
        self.timeList = []

    def ini_file(self):
        with open(self.path, "r") as file:
            lines = file.readlines()
        return lines


    def parser(self):
        """
        此函数用来对日志进行分割，然后针对每个ip创建访问者对象，并写入 self.visitor属性
        :return:
        """
        for line in self.content:
            match_group = re.findall(self.regex, line)
            """
                print(match_group,len(match_group),type(match_group))
                print(type(match_group[0]),len(match_group[0]))
            """
            tempDic = {}

            try:
                length = len(match_group[0])
            except:
                print('[❌] error logs:',line)
                continue

            table = ['ip','time','method_and_uri','status','content-length','','user_agent']
            for i in range(1,length):
                try:
                    tempDic[table[i]] = match_group[0][i]
                except:
                    print('[❌] error logs:', line)
                    continue

            ip = match_group[0][0]
            if ip not in self.ipList.keys():
                self.ipList[ip] = [tempDic,]
            else:
                self.ipList[ip].append(tempDic)

        # print(self.ipList)



    def check(self):
        """
        此函数用来对self.visitor属性进行检查，比如统计带有攻击行为的ip
        :return:
        """
        return 123

    def save_result(self):
        """
        此函数用来按照格式生成统计日志
        :return:
        """

    def run(self):
        self.parser()
        self.check()
        if RESULT_LOG:
            self.save_result()
