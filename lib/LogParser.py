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
        self.ipList = {}

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

    def time_log(self):
        time_local = time.localtime(time.time())

        start_time = "2021-08-14 00:00:00"
        end_time = "2021-08-15 00:00:00"

        start_time = time.strptime(start_time, "%Y-%m-%d %H:%M:%S")
        start_time = int(time.mktime(start_time))

        end_time = time.strptime(end_time, "%Y-%m-%d %H:%M:%S")
        end_time = int(time.mktime(end_time))

        self.judge_ddos(start_time,end_time)

        return
    def judge_ddos(self,start_time,end_time):
        # 只需要记录每小时即可，其他数据无意义。

        total_time = []

        month_dict = {'Jan': 1, 'Feb': 2, 'Mar': 3, 'Apr': 4, 'May': 5,
                           'Jun': 6, 'Jul': 7, 'Aug': 8, 'Sep': 9, 'Oct': 10,
                           'Nov': 11, 'Dec': 12}

        hour_count = 0
        for time_loop in range(int(start_time),end_time,3600):
            for ip in self.ipList.keys():
                for item in self.ipList[ip]:
                    # 分离数据
                    day = item['time'][0:2]
                    mon = month_dict[item['time'][3:6]]
                    yr = item['time'][7:11]
                    hr = item['time'][12:14]
                    minute = item['time'][15:17]
                    sec = item['time'][18:20]

                    # 构建时间戳
                    temp_time = ('%s-%s-%s %s:%s:%s')%(yr,mon,day,hr,minute,sec)
                    timeArray = time.strptime(temp_time, "%Y-%m-%d %H:%M:%S")
                    timestamp = time.mktime(timeArray)
                    total_time.append(timestamp)

                    # print(timestamp)
                    # 统计每小时访问量
                    if timestamp in range(time_loop,time_loop+3600):
                        hour_count += 1

            # 转换成时间戳并输出
            out_time = time.localtime(time_loop)
            out_time = time.strftime("%Y-%m-%d %H:%M:%S", out_time)
            print(f"[✅]{out_time} count : {hour_count}")
            hour_count =0
        return
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
        self.time_log()

        return


    def run(self):
        self.parser()
        self.check()
        if RESULT_LOG:
            self.save_result()
