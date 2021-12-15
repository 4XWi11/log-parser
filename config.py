
#匹配日志的正则
REGEX_LOG_NGINX = r"(.*)\s-\s-\s\[(.*)]\s\"(.*)\"\s(\d+|-)\s(\d+|-)\s\"(.*)\"\s\"(.*)\""
REGEX_LOG_APACHE = r""

REGEX = {
    0: REGEX_LOG_NGINX,
    1: REGEX_LOG_APACHE
}
#生成结果报告

RESULT_LOG = True

RESULT_DEMO = '''Time: %s -- Time: %s : Maybe somebody attack the server From ip(%s) '''