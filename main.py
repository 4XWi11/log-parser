import argparse
from lib.LogParser import LogParser
from config import REGEX


def main():
    arg = argparse.ArgumentParser()
    arg.add_argument("path", help="The log you ready to analyse.", type=str)
    arg.add_argument("type", help="1->nginx_log/ 2->apache_log", type=int)
    path = arg.parse_args().path
    log_type = arg.parse_args().type
    log_parser_new = LogParser(path, REGEX[log_type])
    log_parser_new.run()


if __name__ == '__main__':
    main()
