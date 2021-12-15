from lib.user import NginxVisitor
import re
from config import *


class LogParser:

    def __init__(self, log_path, regex):
        self.path = log_path
        self.regex = regex
        self.content = self.ini_file()
        self.visitor = []

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
            ip = match_group[0]
            time = match_group[1]
            request = match_group[2]
            state = match_group[3]
            user_agent = match_group[5]

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
