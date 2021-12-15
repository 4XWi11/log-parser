import requests
import json


class NginxVisitor:

    """
    @ip: 访问ip ( 127.0.0.1
    @method: 请求头 ( GET/POST……
    @uri: 请求资源路径 ( /xxx/xxx/index.php
    @status： 请求状态码 ( 200/404/500
    @agent：请求代理 ( user-agent
    @time：请求时间 ( 使用字典来记录请求的次数，和时间
    """

    def __init__(self, ip):
        self.ip = ip
        self.data = {}
        self.ip_city = ""
        self.ip_isp = ""
        self.ip_country = ""

    def ip_api(self):
        """ Get IP information from API """

        url = 'http://ip-api.com/json/{0}'.format(self.ip)
        print(url)
        result = requests.get(url, timeout=15)
        ip_data = json.loads(result.text)

        if ip_data['status'] == 'success':
            self.ip_country = ip_data['country']
            self.ip_isp = ip_data['isp']
            self.ip_city = ip_data['city']

        return

    def set_data(self, method, uri, status, agent, time):
        key = len(self.data)
        self.data[key] = {
            "method": method,
            "uri": uri,
            "status": status,
            "agent": agent,
            "time": time
        }

    def data_extract(self):
        return self

    def print(self):
        self.ip_api()
        return
