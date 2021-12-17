import argparse
from lib.LogParser import LogParser
from config import REGEX_LOG_APACHE


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
    path = arg.parse_args().path
    log_parser_new = LogParser(path, REGEX_LOG_APACHE)
    log_parser_new.run()
    print()

def test():
    log_parser_new = LogParser('access.txt',REGEX_LOG_APACHE)
    log_parser_new.run()
    return

if __name__ == '__main__':
    test()
    # main()