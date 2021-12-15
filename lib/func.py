from user import *

def get_log(path="/var/log/apache2/access.log"):
    try:
        f = open(path, 'r')
        lines = f.readlines()
        return lines
    except:
        print("[ERROR] Can't find the log File !!!")
        exit()
    return

def analyse_log(lines):
    # 得到基础信息
    for line in lines:
        obj = nginx_visitor(line)
        obj.print()

    def get_ip_list():
        # 统计出现次数前十的ip

        return

    def get_time_list():
        # 统计每一小时的访问量

        return


def test_data():
    s = '''18.196.96.172 - - [13/Feb/2021:11:17:07 +0100] "GET /.well-known/acme-challenge/Zl0pAQdxHIqQ6s3hDViH5__f414upShE14_yGgsIyao HTTP/1.1" 404 268 "-" "Mozilla/5.0 (compatible; Let's Encrypt validation server; +https://www.letsencrypt.org)"'''
    analyse(s)
