import re
from config import *
import time
import requests
import json

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
        table = ['ip', 'time', 'method_and_uri', 'status', 'content-length', '', 'user_agent']
        month_dict = {'Jan': 1, 'Feb': 2, 'Mar': 3, 'Apr': 4, 'May': 5,
                           'Jun': 6, 'Jul': 7, 'Aug': 8, 'Sep': 9, 'Oct': 10,
                           'Nov': 11, 'Dec': 12}
        time_table = []

        for line in self.content:
            match_group = re.findall(self.regex, line)

            tempDic = {}

            try:
                length = len(match_group[0])
            except:
                print('[❌] error logs:',line)
                continue

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

            _time = tempDic['time']
            day = _time[0:2]
            mon = month_dict[_time[3:6]]
            yr = _time[7:11]
            hr = _time[12:14]
            minute = _time[15:17]
            sec = _time[18:20]

            # 构建时间戳
            temp_time = ('%s-%s-%s %s:%s:%s') % (yr, mon, day, hr, minute, sec)
            timeArray = time.strptime(temp_time, "%Y-%m-%d %H:%M:%S")
            timestamp = time.mktime(timeArray)

            time_table.append(timestamp)

        return time_table
    def ip_api(self,ip):
        """ Get IP information from API """
        url = f'http://ip-api.com/json/{ip}'
        result = requests.get(url, timeout=5)
        ip_data = json.loads(result.text)

        if ip_data['status'] == 'success':
            self.ip_country = ip_data['country']
            self.ip_isp = ip_data['isp']
            self.ip_city = ip_data['city']

        self.ip_infor_output()
        return
    def ip_infor_output(self):
        print("[✅]country:",self.ip_country,'|',
              "isp:",self.ip_isp,'｜'
              "city:",self.ip_city)
        return
    def time_log(self,time_table):
        start_time =  int(min(time_table))

        self.judge_attack(time_table,start_time)

        return
    def time_log_test(self,time_table):
        start_time = "2021-08-04 00:00:00"
        end_time = "2021-08-05 00:00:00"

        start_time = time.strptime(start_time, "%Y-%m-%d %H:%M:%S")
        start_time = int(time.mktime(start_time))

        end_time = time.strptime(end_time, "%Y-%m-%d %H:%M:%S")
        end_time = int(time.mktime(end_time))

        self.judge_attack(time_table,start_time)

        return

    def judge_attack(self,time_table,start_time):
        self.time_log_print(time_table,start_time)
        return

    def time_log_print(self, time_table,start_time):
        end_time = int(time.time())
        for __time in range(start_time,end_time,3600*24):
            self.hr_time_log_print(time_table, __time)
        return

    def hr_time_log_print(self, time_table,start_time):
        hour_table = {0: 0,1:0,2:0,3:0,4:0,5:0,6:0,7:0,8:0,9:0,10:0,11:0,12:0,
                      13:0,14:0,15:0,16:0,17:0,18:0,19:0,20:0,21:0,22:0,23:0}
        indice = 0
        hour_indice = 0

        if start_time > max(time_table):
            return

        time_temp = time.localtime(start_time)
        time_array = time.strftime("%Y-%m-%d %H:%M:%S", time_temp)

        basic_hour_num = int(time_array[5:7])

        while indice<len(time_table) and hour_indice <24:
            _time = time_table[indice]
            temp = _time - start_time
            if temp < 3600 and temp > 0:
                hour_table[(hour_indice+basic_hour_num)%24] += 1
                indice += 1
            elif temp < 0:
                indice += 1
            else:
                out_time = time.localtime(start_time)

                out_time = time.strftime("%Y-%m-%d %H:%M:%S", out_time)
                print(f"[✅] {out_time} count : {hour_table[hour_indice]}")
                hour_indice += 1
                start_time += 3600

        print('--------------------------------')
        return
    def check(self,time_table):
        """
        此函数用来对self.visitor属性进行检查，比如统计带有攻击行为的ip
        :return:
        """
        sensitive_word_dic = ['shell','backdoor','$',r'../','chmod','wget','system','popen','exec','runtime']
        for item in self.ipList.values():
            url = item[0]['method_and_uri']
            for sensitive_word_item in sensitive_word_dic:
                if sensitive_word_item in url:
                    print(f'[❌] May be the Attacker !!! {url}')

        self.time_log(time_table)

        return True
    def save_result(self):
        """
        此函数用来按照格式生成统计日志
        :return:
        """
        return
    def run(self):
        time_table = self.parser()
        self.check(time_table)
        if RESULT_LOG:
            self.save_result()
