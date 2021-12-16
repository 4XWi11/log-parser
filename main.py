import argparse
from lib.LogParser import LogParser
from config import REGEX


def main():
    print('''_   _                     _                                               
| | | |_____ __  _   _    | |    ___   __ _      _ __   __ _ _ __ ___  ___  
| |_| |_  / '_ \| | | |   | |   / _ \ / _` |    | '_ \ / _` | '__/ __|/ _ \\
|  _  |/ /| | | | |_| |   | |__| (_) | (_| |    | |_) | (_| | |  \__ \  __/
|_| |_/___|_| |_|\__,_|___|_____\___/ \__, |____| .__/ \__,_|_|  |___/\___| 
                     |_____|          |___/_____|_|                         
''')
    arg = argparse.ArgumentParser()
    arg.add_argument("--path", help="The log you ready to analyse.", type=str)
    arg.add_argument("--type", help="0->apache_log/ 1->apache_log", type=int)
    path = arg.parse_args().path
    log_type = arg.parse_args().type
    log_parser_new = LogParser(path, REGEX[log_type])
    log_parser_new.run()
    print()

def test():
    log_parser_new = LogParser('access.txt',REGEX[0])
    log_parser_new.run()
    return

if __name__ == '__main__':
    test()
    # main()