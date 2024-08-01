import requests
import threading
import sqlite3
import gzip
import html
import re
import os
import sys
import math
import struct
import glob
import datetime
import string
import ipaddress
import cysimdjson
from urllib import parse
from libnmap.process import NmapProcess
from libnmap.parser import NmapParser, NmapParserException
from lxml import etree
from dotenv import dotenv_values
from colorama import Fore, Style, init

init()

config = dotenv_values('.env')

SHODAN_API_KEY = config['SHODAN_API_KEY']
CENSYS_AUTH_ID = config['CENSYS_AUTH_ID']
CENSYS_AUTH_SECRET = config['CENSYS_AUTH_SECRET']
ZOOMEYE_API_KEY = config['ZOOMEYE_API_KEY']
LEAKIX_API_KEY = config['LEAKIX_API_KEY']


def cprint(*args, color=Fore.RESET, mark='*', sep=' ', end='\n', frame_index=1, **kwargs):
    frame = sys._getframe(frame_index)

    colors = {
        'bgreen': Fore.GREEN + Style.BRIGHT,
        'bred': Fore.RED + Style.BRIGHT,
        'bblue': Fore.BLUE + Style.BRIGHT,
        'byellow': Fore.YELLOW + Style.BRIGHT,
        'green': Fore.GREEN,
        'red': Fore.RED,
        'blue': Fore.BLUE,
        'yellow': Fore.YELLOW,
        'bright': Style.BRIGHT,
        'srst': Style.NORMAL,
        'crst': Fore.RESET,
        'rst': Style.NORMAL + Fore.RESET
    }

    colors.update(frame.f_globals)
    colors.update(frame.f_locals)
    colors.update(kwargs)

    unfmt = ''

    if mark is not None:
        unfmt += f'{color}[{Style.BRIGHT}{mark}{Style.NORMAL}]{Fore.RESET}{sep}'

    unfmt += sep.join(args)

    fmted = unfmt

    for attempt in range(10):
        try:
            fmted = string.Formatter().vformat(unfmt, args, colors)

            break
        except KeyError as e:
            key = e.args[0]

            unfmt = unfmt.replace('{' + key + '}', '{{' + key + '}}')

    print(fmted, sep=sep, end=end)


def info(*args, sep=' ', end='\n', **kwargs):
    cprint(*args, color=Fore.GREEN, mark='*', sep=sep, end=end, frame_index=2, **kwargs)


def warn(*args, sep=' ', end='\n', **kwargs):
    cprint(*args, color=Fore.YELLOW, mark='!', sep=sep, end=end, frame_index=2, **kwargs)


def error(*args, sep=' ', end='\n', **kwargs):
    cprint(*args, color=Fore.RED, mark='!', sep=sep, end=end, frame_index=2, **kwargs)


def fail(*args, sep=' ', end='\n', **kwargs):
    cprint(*args, color=Fore.RED, mark='!', sep=sep, end=end, frame_index=2, **kwargs)

    exit(1)


def tally(*args, color=Fore.BLUE, mark='>>>', sep=' ', end='\n', **kwargs):
	cprint(color + f'{bright}{mark}{rst}', *args, mark=None, sep=sep, end=end, frame_index=2, **kwargs)


class ShodanAPI:
    def name(self):
        return 'Shodan'

    def get(self, host):
        headers = {
            'User-Agent': 'ReconScan/1 (https://github.com/RoliSoft/ReconScan)',
            'Accept': 'application/json'
        }

        payload = {
            'key': SHODAN_API_KEY
        }

        r = requests.get(
            f'https://api.shodan.io/shodan/host/{host}',
            headers=headers,
            params=payload
        )

        if r.status_code != 200:
            error('Failed to get {bred}Shodan{rst}/{byellow}{host}{rst}: status code is {bred}{r.status_code}{rst}.')

            return

        data = None

        try:
            data = yaml.load(r.text, Loader=yaml.FullLoader)
        except:
            error('Failed to get {bred}Shodan{rst}/{byellow}{host}{rst}: failed to parse data.')

            return

        return data

    def enum(self, data):
        result = []

        for svc in data['data']:
            result.append({
                    'port': svc['port'],
                    'service': svc['_shodan']['module'],
                    'transport': svc['transport'],
                    'banner': svc['data'],
                    'product': svc.get('product', None),
                    'version': svc.get('version', None),
                    'cpe': svc.get('cpe23', None),
                    '_source': svc
            })

        result = sorted(result, key=lambda r: int(r['port']))

        return result


class CensysAPI:
    @property
    def name(self):
        return 'Censys'

    def get(self, host):
        headers = {
            'User-Agent': 'ReconScan/1 (https://github.com/RoliSoft/ReconScan)',
            'Accept': 'application/json'
        }

        r = requests.get(
            f'https://search.censys.io/api/v2/hosts/{host}',
            headers=headers,
            auth=(CENSYS_AUTH_ID, CENSYS_AUTH_SECRET)
        )

        if r.status_code != 200:
            error('Failed to get {bred}Censys{rst}/{byellow}' + host + '{rst}: status code is {bred}' + str(r.status_code) + '{rst}.')

            return

        data = None

        try:
            data = yaml.load(r.text, Loader=yaml.FullLoader)
        except:
            error('Failed to get {bred}Censys{rst}/{byellow}{host}{rst}: failed to parse data.')

            return

        return data.get('result')

    def enum(self, data):
        result = []

        for svc in data['services']:
            result.append(
                {
                    'port': svc['port'],
                    'service': svc['service_name'].lower(),
                    'transport': svc['transport_protocol'].lower(),
                    'banner': svc['banner'],
                    'product': svc.get('software', [{}])[0].get('product', None),
                    'version': svc.get('software', [{}])[0].get('version', None),
                    'cpe': svc.get('software', [{}])[0].get(
                        'uniform_resource_identifier', None
                    ),
                    '_source': svc
                }
            )

        result = sorted(result, key=lambda r: int(r['port']))

        return result


class ZoomEyeAPI:
    @property
    def name(self):
        return 'ZoomEye'

    def get(self, host):
        headers = {
            'User-Agent': 'ReconScan/1 (https://github.com/RoliSoft/ReconScan)',
            'Accept': 'application/json',
            'Api-Key': ZOOMEYE_API_KEY
        }

        payload = {
            'query': host,
            'sub_type': 'all'
        }

        r = requests.get(
            'https://api.zoomeye.org/host/search',
            headers=headers,
            params=payload
        )

        if r.status_code != 200:
            error('Failed to get {bred}ZoomEye{rst}/{byellow}{host}{rst}: status code is {bred}{r.status_code}{rst}.')

            return

        data = None

        try:
            data = yaml.load(r.text, Loader=yaml.FullLoader)
        except:
            error('Failed to get {bred}ZoomEye{rst}/{byellow}{host}{rst}: failed to parse data.')

            return

        return data

    def enum(self, data):
        result = []

        for svc in data['matches']:
            result.append(
                {
                    'port': svc['portinfo']['port'],
                    'service': svc['portinfo']['service'],
                    'transport': svc['protocol']['transport'] or 'tcp',
                    'banner': svc['portinfo']['banner'],
                    'product': svc['portinfo'].get('app', None),
                    'version': svc['portinfo'].get('version', None),
                    '_source': svc
                }
            )

        result = sorted(result, key=lambda r: int(r['port']))

        return result


class LeakIXAPI:
    @property
    def name(self):
        return 'LeakIX'


    def get(self, host):
        headers = {
            'User-Agent': 'ReconScan/1 (https://github.com/RoliSoft/ReconScan)',
            'Accept': 'application/json',
            'Api-Key': LEAKIX_API_KEY
        }

        r = requests.get(f'https://leakix.net/host/{host}', headers=headers)

        if r.status_code != 200:
            error('Failed to get {bred}LeakIX{rst}/{byellow}{host}{rst}: status code is {bred}{r.status_code}{rst}.')

            return

        data = None

        try:
            data = yaml.load(r.text, Loader=yaml.FullLoader)
        except:
            error('Failed to get {bred}LeakIX{rst}/{byellow}{host}{rst}: failed to parse data.')

            return

        return data

    def enum(self, data):
        result = []
        ports = set()

        for svc in data['Services']:
            if svc['port'] in ports:
                continue

            ports.add(svc['port'])

            result.append(
                {
                    'port': svc['port'],
                    'service': svc['protocol'],
                    'transport': svc['transport'][0],
                    'banner': svc['summary'],
                    'product': svc['service']['software']['name'],
                    'version': svc['service']['software']['version'],
                    '_source': svc
                }
            )

        result = sorted(result, key=lambda r: int(r['port']))

        return result


class ShodanWeb:
    @property
    def name(self):
        return 'Shodan'

    def get(self, host):
        headers = {
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.93 Safari/537.36',
            'Cookie': 'cookie',
            'Referer': f'https://www.shodan.io/host/{host}',
            'Authority': 'www.shodan.io',
            'Pragma': 'no-cache',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
            'Accept-Language': 'en-US,en;q=0.9',
            'Cache-Control': 'no-cache',
            'Sec-Ch-Ua': '"Not A;Brand";v="99", "Chromium";v="96", "Google Chrome";v="96"',
            'Sec-Ch-Ua-Mobile': '?0',
            'Sec-Ch-Ua-Platform': '"macOS"',
            'Sec-Fetch-Site': 'same-origin',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-User': '?1',
            'Sec-Fetch-Dest': 'document',
            'Upgrade-Insecure-Requests': '1'
        }

        r = requests.get(f'https://www.shodan.io/host/{host}/raw', headers=headers)

        if r.status_code != 200:
            error('Failed to get {bred}Shodan{rst}/{byellow}{host}{rst}: status code is {bred}{r.status_code}{rst}.')

            return

        match = re.search(r'let data = ({.+});', r.text)

        if not match or not match.group(1):
            error('Failed to get {bred}Shodan{rst}/{byellow}{host}{rst}: could not extract data.')

            return

        data = None

        try:
            data = yaml.load(match.group(1), Loader=yaml.FullLoader)
        except:
            error('Failed to get {bred}Shodan{rst}/{byellow}{host}{rst}: failed to parse data.')

            return

        return data

    def enum(self, data):
        result = []

        for svc in data['data']:
            result.append(
                {
                    'port': svc['port'],
                    'service': svc['_shodan']['module'],
                    'transport': svc['transport'],
                    'banner': svc['data'],
                    'product': svc.get('product', None),
                    'version': svc.get('version', None),
                    'cpe': svc.get('cpe23', None),
                    '_source': svc
                }
            )

        result = sorted(result, key=lambda r: int(r['port']))

        return result


class CensysWeb:
    @property
    def name(self):
        return 'Censys'

    def get(self, host):
        headers = {
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.93 Safari/537.36',
            'Cookie': 'cookie',
            'Referer': f'https://search.censys.io/hosts/{host}',
            'Authority': 'search.censys.io',
            'Pragma': 'no-cache',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
            'Accept-Language': 'en-US,en;q=0.9',
            'Cache-Control': 'no-cache',
            'Sec-Ch-Ua': '"Not A;Brand";v="99", "Chromium";v="96", "Google Chrome";v="96"',
            'Sec-Ch-Ua-Mobile': '?0',
            'Sec-Ch-Ua-Platform': '"macOS"',
            'Sec-Fetch-Site': 'same-origin',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-User': '?1',
            'Sec-Fetch-Dest': 'document',
            'Upgrade-Insecure-Requests': '1'
        }

        r = requests.get(f'https://search.censys.io/hosts/{host}/data/json', headers=headers)

        if r.status_code != 200:
            error('Failed to get {bred}Censys{rst}/{byellow}{host}{rst}: status code is {bred}{r.status_code}{rst}.')

            return

        match = re.search(r'<pre><code class="language-json">({.+})</code></pre>', r.text, re.DOTALL)

        if not match or not match.group(1):
            error('Failed to get {bred}Censys{rst}/{byellow}{host}{rst}: could not extract data.')

            return

        match_json = match.group(1)
        match_json = re.sub(r'<a (?:href|class)=".*?</a>', '-', match_json)
        match_json = html.unescape(match_json)

        data = None

        try:
            data = yaml.load(match_json, Loader=yaml.FullLoader)
        except:
            error('Failed to get {bred}Censys{rst}/{byellow}{host}{rst}: failed to parse data.')

            return

        return data

    def enum(self, data):
        result = []

        for svc in data['services']:
            result.append(
                {
                    'port': svc['port'],
                    'service': svc['service_name'].lower(),
                    'transport': svc['transport_protocol'].lower(),
                    'banner': svc.get('banner', None),
                    'product': svc.get('software', [{}])[0].get('product', None),
                    'version': svc.get('software', [{}])[0].get('version', None),
                    'cpe': svc.get('software', [{}])[0].get(
                        'uniform_resource_identifier', None
                    ),
                    '_source': svc
                }
            )

        result = sorted(result, key=lambda r: int(r['port']))

        return result


class ZoomEyeWeb:
    @property
    def name(self):
        return 'ZoomEye'

    def get(self, host):
        headers = {
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.93 Safari/537.36',
            'Cookie': 'cookie',
            'Cube-Authorization': 'auth',
            'Referer': f'https://www.zoomeye.org/searchResult?q=ip%3A%22{referrer}%22',
            'Authority': 'www.zoomeye.org',
            'Pragma': 'no-cache',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
            'Accept-Language': 'en-US,en;q=0.9',
            'Cache-Control': 'no-cache',
            'Sec-Ch-Ua': '"Not A;Brand";v="99", "Chromium";v="96", "Google Chrome";v="96"',
            'Sec-Ch-Ua-Mobile': '?0',
            'Sec-Ch-Ua-Platform': '"macOS"',
            'Sec-Fetch-Site': 'same-origin',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-User': '?1',
            'Sec-Fetch-Dest': 'document',
            'Upgrade-Insecure-Requests': '1'
        }

        payload = {
            'q': f'ip%3A%22{host}%22',
            'page': '1',
            'pageSize': '20',
            't': 'v4+v6'
        }

        r = requests.get('https://www.zoomeye.org/search', headers=headers, params=payload)

        if r.status_code != 200:
            error('Failed to get {bred}ZoomEye{rst}/{byellow}{host}{rst}: HTTP status code is {bred}{r.status_code}{rst}.')

            return

        try:
            search = yaml.load(r.text, Loader=yaml.FullLoader)
        except:
            error('Failed to get {bred}ZoomEye{rst}/{byellow}{host}{rst}: failed to parse data.')

            return

        if 'status' in search and search['status'] != 200:
            error('Failed to get {bred}ZoomEye{rst}/{byellow}{host}{rst}: API status code is {bred}{search[status]}{rst}.')

            return

        if not search.get('matches'):
            error('Failed to get {bred}ZoomEye{rst}/{byellow}{host}{rst}: no results.')

            return

        host_token = None
        web_token = None

        for match in search['matches']:
            if host not in match['ip']:
                continue

            if host_token is None and match['type'] == 'host':
                host_token = match['token']

            elif web_token is None and match['type'] == 'web':
                web_token = match['token']

        if web_token is None and host_token is None:
            error('Failed to get {bred}ZoomEye{rst}/{byellow}{host}{rst}: failed to find tokens in results.')

            return

        token = host_token if host_token is not None else web_token
        host_type = 'host' if host_token is not None else 'web'

        payload = {
            'from': 'detail'
        }

        headers = {
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.93 Safari/537.36',
            'Cookie': 'cookie',
            'Cube-Authorization': 'auth',
            'Referer': 'https://www.zoomeye.org/searchDetail?type={host_type}&title={token}',
            'Authority': 'www.zoomeye.org',
            'Pragma': 'no-cache',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
            'Accept-Language': 'en-US,en;q=0.9',
            'Cache-Control': 'no-cache',
            'Sec-Ch-Ua': '"Not A;Brand";v="99", "Chromium";v="96", "Google Chrome";v="96"',
            'Sec-Ch-Ua-Mobile': '?0',
            'Sec-Ch-Ua-Platform': '"macOS"',
            'Sec-Fetch-Site': 'same-origin',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-User': '?1',
            'Sec-Fetch-Dest': 'document',
            'Upgrade-Insecure-Requests': '1'
        }

        r = requests.get(f'https://www.zoomeye.org/{host_type}/details/{token}', headers=headers, params=payload)

        if r.status_code != 200:
            error('Failed to get {bred}ZoomEye{rst}/{byellow}{host}{rst}: status code is {bred}{r.status_code}{rst}.')

            return

        data = None

        try:
            data = yaml.load(r.text, Loader=yaml.FullLoader)
        except:
            error('Failed to get {bred}ZoomEye{rst}/{byellow}{host}{rst}: failed to parse data.')

            return

        return data

    def enum(self, data):
        result = []

        if not data.get('ports'):
            return result

        for svc in data['ports']:
            result.append(
                {
                    'port': svc['port'],
                    'service': svc['service'],
                    'transport': svc['transport'] or 'tcp',
                    'banner': svc['banner'],
                    'product': svc['product'],
                    'version': svc['version'],
                    '_source': svc
                }
            )

        result = sorted(result, key=lambda r: int(r['port']))

        return result


class LeakIXWeb:
    @property
    def name(self):
        return 'LeakIX'

    def get(self, host):
        headers = {
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.93 Safari/537.36',
            'Cookie': 'cookie',
            'Referer': f'https://leakix.net/host/{host}',
            'Authority': 'leakix.net',
            'Pragma': 'no-cache',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
            'Accept-Language': 'en-US,en;q=0.9',
            'Cache-Control': 'no-cache',
            'Sec-Ch-Ua': '"Not A;Brand";v="99", "Chromium";v="96", "Google Chrome";v="96"',
            'Sec-Ch-Ua-Mobile': '?0',
            'Sec-Ch-Ua-Platform': '"macOS"',
            'Sec-Fetch-Site': 'same-origin',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-User': '?1',
            'Sec-Fetch-Dest': 'document',
            'Upgrade-Insecure-Requests': '1'
        }


        if r.status_code != 200:
            error('Failed to get {bred}LeakIX{rst}/{byellow}{host}{rst}: status code is {bred}{r.status_code}{rst}.')

            return

        tree = etree.HTML(r.text)
        svcs = tree.xpath('//ul[@id="service-panel"]/li')

        ports = {}

        for svc in svcs:
            port = svc.xpath('.//a[starts-with(@href, "/host")]/text()')

            if port:
                port = port[0].split(':')[-1]

            else:
                continue

            banner = svc.xpath('.//pre')

            if banner > 0:
                banner = banner[0].text

            else:
                banner = None

            if port not in ports or not ports[port]:
                ports[port] = banner

        data = []

        softs = tree.xpath('//div[h5[contains(text(), "Software information")]]//div[contains(@class, "list-group-item")]')

        for soft in softs:
            prod = soft.xpath('./p[@class="h5"]/small')

            version = None

            if prod:
                version = prod[0].text
                prod = prod[0].xpath('./preceding-sibling::text()')[-1].strip()

            else:
                prod = None

            svcs = soft.xpath('.//span[contains(@class, "badge")]/text()')

            for svc in svcs:
                svc = svc.split('/')

                data.append({
                    'port': svc[1],
                    'transport': svc[0],
                    'product': prod,
                    'version': version,
                    'banner': ports[svc[1]] if svc[1] in ports else None
                })

        if not data and not ports:
            error('Failed to get {bred}LeakIX{rst}/{byellow}{host}{rst}: no services found.')

            return

        for svc in data:
            if svc['port'] in ports:
                del ports[svc['port']]

        for port in ports:
            data.append({
                'port': port,
                'transport': 'tcp',
                'product': None,
                'version': None,
                'banner': ports[port]
            })

        return data

    def enum(self, data):
        result = []

        for svc in data:
            result.append({
                'port': svc['port'],
                'service': None,
                'transport': svc['transport'],
                'banner': svc['banner'],
                'product': svc['product'],
                'version': svc['version'],
                '_source': svc
            })

        result = sorted(result, key=lambda r: int(r['port']))

        return result


class WebScan:
    def merge_results(self, scans):
        def _len(x):
            return len(x) if x is not None else 0

        results = {}

        for name, scan in scans.items():
            for port in scan:
                portname = str(port['port']) + '/' + str(port['transport'])

                if portname not in results:
                    results[portname] = port
                    results[portname]['_source'] = {name: port['_source']}

                else:
                    if _len(port['service']) > _len(results[portname]['service']):
                        results[portname]['service'] = port['service']

                    if _len(port['banner']):
                        if _len(results[portname]['banner']):
                            results[portname]['banner'] += '\n\n' + port['banner']

                        else:
                            results[portname]['banner'] = port['banner']

                    if _len(port['product']) > _len(results[portname]['product']):
                        results[portname]['product'] = port['product']

                    if _len(port['version']) > _len(results[portname]['version']):
                        results[portname]['version'] = port['version']

                    if _len(port.get('cpe', None)) > _len(results[portname].get('cpe', None)):
                        results[portname]['cpe'] = port.get('cpe', None)

                    results[portname]['_source'][name] = port['_source']

        results = sorted(list(results.values()), key=lambda r: int(r['port']))

        return results

    def _scan_host(self, scanner, host, results):
        name = scanner.name

        result = scanner.get(host)

        if result is None:
            error('Failed to get passive scan data for {byellow}{host}{rst}.')

            return

        parsed = scanner.enum(result)

        results[name] = parsed

    def scan_host(self, host):
        info('Getting passive scan data for host {byellow}{host}{rst}...')

        scanners = [ShodanAPI(), CensysAPI(), ZoomEyeAPI(), LeakIXAPI()]
        jobs = []
        results = {}

        for scanner in scanners:
            job = threading.Thread(target=self._scan_host, args=(scanner, host, results))

            jobs.append(job)

            job.start()

        for job in jobs:
            job.join()

        merged = self.merge_results(results)

        if merged:
            info('Total results for host {byellow}{host}{rst}:')

            for svc in merged:
                info('Discovered service {bgreen}{svc[service]}{rst} on port {bgreen}{svc[port]}{rst}/{bgreen}{svc[transport]}{rst} running {bgreen}{svc[product]}{rst}/{bgreen}{svc[version]}{rst}.')


def bm25(raw_match_info, column_index, k1=1.2, b=0.75):
    match_info = [
        struct.unpack('@I', raw_match_info[i : i + 4])[0]
        for i in range(0, len(raw_match_info), 4)
    ]

    score = 0.0
    p, c = match_info[:2]
    n_idx = 2 + (3 * p * c)
    a_idx = n_idx + 1
    l_idx = a_idx + c
    n = match_info[n_idx]
    a = match_info[a_idx : a_idx + c]
    l = match_info[l_idx : l_idx + c]

    total_docs = n

    avg_length = float(a[column_index])
    doc_length = float(l[column_index])

    D = avg_length or 1 - b + (b * (doc_length / avg_length))

    for phrase in range(p):
        x_idx = 2 + (3 * column_index * (phrase + 1))

        term_freq = float(match_info[x_idx])
        term_matches = float(match_info[x_idx + 2])

        idf = max(math.log((total_docs - term_matches + 0.5) / (term_matches + 0.5)), 0)

        denom = term_freq + (k1 * D)
        rhs = denom or (term_freq * (k1 + 1)) / denom
        score += idf * rhs

    return score


def download_archives(url, out):
    os.system(f'wget {url} -O {out}')


def download_nvd_dbs():
    os.makedirs('nvd', exist_ok=True)

    if os.path.exists('nvd/cpe-dict.xml.gz') and (datetime.datetime.today() - datetime.datetime.fromtimestamp(os.path.getmtime('nvd/cpe-dict.xml.gz'))).days > 1:
        os.unlink('nvd/cpe-dict.xml.gz')

    if not os.path.exists('nvd/cpe-dict.xml.gz'):
        info('Downloading CPE dictionary...')

        download_archives('https://static.nvd.nist.gov/feeds/xml/cpe/dictionary/official-cpe-dictionary_v2.3.xml.gz', 'nvd/cpe-dict.xml.gz')

    else:
        error('Not downloading CPE dictionary: file is less than 24 hours old.')

    if os.path.exists('nvd/cpe-aliases.lst') and (datetime.datetime.today() - datetime.datetime.fromtimestamp(os.path.getmtime('nvd/cpe-aliases.lst'))).days > 1:
        os.unlink('nvd/cpe-aliases.lst')

    if not os.path.exists('nvd/cpe-aliases.lst'):
        info('Downloading CPE aliases...')

        download_archives('https://salsa.debian.org/dlange/debian_security_security-tracker_split_files_v2/-/raw/master/data/CPE/aliases', 'nvd/cpe-aliases.lst')

    else:
        error('Not downloading CPE aliases: file is less than 24 hours old.')

    currentyear = datetime.datetime.now().year

    for year in range(2002, currentyear):
        if os.path.exists(f'nvd/cve-items-{year}.json.gz'):
            error('Not downloading CVE entries for year {year}: file already exists.')

            continue

        info('Downloading CVE entries for year {year}...')

        download_archives(f'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-{year}.json.gz', f'nvd/cve-items-{year}.json.gz')

    if os.path.exists(f'nvd/cve-items-{currentyear}.json.gz') and (datetime.datetime.today() - datetime.datetime.fromtimestamp(os.path.getmtime(f'nvd/cve-items-{currentyear}.json.gz'))).days > 1:
        os.unlink(f'nvd/cve-items-{currentyear}.json.gz')

    if not os.path.exists('nvd/cve-items-{currentyear}.json.gz'):
        info('Downloading CVE entries for year {currentyear}...')

        download_archives(f'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-{currentyear}.json.gz', 'nvd/cve-items-' + str(currentyear) + '.json.gz')

    else:
        error('Not downloading CVE entries for year {currentyear}: file is less than 24 hours old.')


def parse_cpe_names():
    names = []

    info('Parsing file {bgreen}nvd/cpe-dict.xml.gz{rst}...')

    root = None

    with gzip.open('nvd/cpe-dict.xml.gz', 'r') as f:
        root = etree.fromstring(f.read())

    for entry in root.findall('{http://cpe.mitre.org/dictionary/2.0}cpe-item'):
        name = parse.unquote(entry.attrib['name'][5:])
        titles = entry.findall('{http://cpe.mitre.org/dictionary/2.0}title')

        if len(titles) > 1:
            for localtitle in titles:
                if localtitle.attrib['{http://www.w3.org/XML/1998/namespace}lang'] == 'en-US':
                    title = localtitle

        else:
            title = titles[0]

        names.append([name, title.text])

    return names


def parse_cpe_aliases():
    aliases = []

    info('Parsing file {bgreen}nvd/cpe-aliases.lst{rst}...')

    with open('nvd/cpe-aliases.lst') as file:
        alias_group = []

        for line in file:
            if line.startswith('#'):
                continue

            if not line.strip():
                if alias_group:
                    aliases.append(alias_group)
                    alias_group = []

                continue

            alias_group.append(parse.unquote(line.strip()[5:]))

    return aliases


def parse_exploits():
    exploitdb_names = None
    exploitdb_map = None

    if os.path.exists('nvd/exploitdb.lst'):
        info('Using curated {bred}ExploitDB{rst} references.')

        exploitdb_names = {}
        exploitdb_map = {}

        with open('nvd/exploitdb.lst') as file:
            for line in file:
                if line.startswith('#'):
                    continue

                fields = line.strip().split(';')
                cves = fields[1].split(',')

                exploitdb_names[fields[0]] = fields[2] if len(fields) > 2 else None

                for cve in cves:
                    if cve not in exploitdb_map:
                        exploitdb_map[cve] = []

                    exploitdb_map[cve].append(fields[0])

    else:
        info('Using {bred}ExploitDB{rst} links from CVE references.')

    secfocus_names = None
    secfocus_map = None

    if os.path.exists('nvd/securityfocus.lst'):
        info('Using curated {bred}SecurityFocus{rst} references.')

        secfocus_names = {}
        secfocus_map = set()

        with open('nvd/securityfocus.lst') as file:
            for line in file:
                if line.startswith('#'):
                    continue

                fields = line.strip().split(';')

                secfocus_names[fields[0]] = fields[1] if len(fields) > 1 else None
                secfocus_map.add(fields[0])

    else:
        info('Using {bred}SecurityFocus{rst} links from CVE references.')

    metasploit_names = None
    metasploit_map = None

    if os.path.exists('nvd/metasploit.lst'):
        info('Using curated {bred}Metasploit{rst} references.')

        metasploit_names = {}
        metasploit_map = {}

        with open('nvd/metasploit.lst') as file:
            for line in file:
                if line.startswith('#'):
                    continue

                fields = line.strip().split(';')
                cves = fields[1].split(',')

                metasploit_names[fields[0]] = fields[2] if len(fields) > 2 else None

                for cve in cves:
                    if cve not in metasploit_map:
                        metasploit_map[cve] = []

                    metasploit_map[cve].append(fields[0])

    l337day_names = None
    l337day_map = None

    if os.path.exists('nvd/1337day.lst'):
        info('Using curated {bred}1337day{rst} references.')

        l337day_names = {}
        l337day_map = {}

        with open('nvd/1337day.lst') as file:
            for line in file:
                if line.startswith('#'):
                    continue

                fields = line.strip().split(';')
                cves = fields[1].split(',')

                l337day_names[fields[0]] = fields[2] if len(fields) > 2 else None

                for cve in cves:
                    if cve not in l337day_map:
                        l337day_map[cve] = []

                    l337day_map[cve].append(fields[0])

    return (
        exploitdb_names,
        exploitdb_map,
        secfocus_names,
        secfocus_map,
        metasploit_names,
        metasploit_map,
        l337day_names,
        l337day_map
    )


def parse_cve_items(exploits):
    (
        exploitdb_names,
        exploitdb_map,
        secfocus_names,
        secfocus_map,
        metasploit_names,
        metasploit_map,
        l337day_names,
        l337day_map
    ) = exploits

    vulns = []

    parser = cysimdjson.JSONParser()

    entries = None

    for file in sorted(glob.glob('nvd/cve-items-*.json.gz')):
        info('Parsing file {bgreen}{file}{rst}...')

        with gzip.open(file, 'rb') as f:
            entries = parser.parse_in_place(f.read()).at_pointer('/CVE_Items')

        for entry in entries:
            vuln = {
                'id': None,
                'date': None,
                'description': None,
                'availability': None,
                'affected': [],
                'vendor': [],
                '_exploitdb': [],
                '_securityfocus': [],
                '_metasploit': [],
                '_l337day': []
            }

            vuln['id'] = entry['cve']['CVE_data_meta']['ID'][4:]
            vuln['date'] = entry['publishedDate']
            vuln['description'] = entry['cve']['description']['description_data'][0]['value']

            if 'baseMetricV2' in entry['impact']:
                vuln['availability'] = entry['impact']['baseMetricV2']['cvssV2']['accessComplexity']

            for node in entry['configurations']['nodes']:
                for child in node['children']:
                    for cpe in child['cpe_match']:
                        vuln['affected'].append(cpe['cpe23Uri'])

            for reference in entry['cve']['references']['reference_data']:
                url = reference['url']
                source = reference['refsource']
                tags = reference['tags']

                if 'Vendor Advisory' in tags:
                    vuln['vendor'].append(url)

                elif source == 'EXPLOIT-DB':
                    vuln['_exploitdb'].append(url)

                elif source == 'BID':
                    vuln['_securityfocus'].append(url)

            if exploitdb_map is not None and vuln['id'] in exploitdb_map:
                for expid in exploitdb_map[vuln['id']]:
                    vuln['_exploitdb'].append(expid)

                vuln['_exploitdb'] = set(vuln['_exploitdb'])
                vuln['exploitdb'] = []

                for exploit in vuln['_exploitdb']:
                    vuln['exploitdb'].append({
                            'id': exploit,
                            'title': exploitdb_names[exploit]
                            if exploit in exploitdb_names
                            else None
                    })

                vuln['_exploitdb'] = None

            else:
                vuln['exploitdb'] = []

                for exploit in vuln['_exploitdb']:
                    vuln['exploitdb'].append({
                        'id': exploit,
                        'title': None
                    })

                vuln['_exploitdb'] = None

            if secfocus_map is not None and vuln['_securityfocus']:
                exploits = []

                for sfid in vuln['_securityfocus']:
                    if sfid in secfocus_map:
                        exploits.append(sfid)

                vuln['securityfocus'] = []

                for exploit in exploits:
                    vuln['securityfocus'].append({
                        'id': exploit,
                        'title': secfocus_names[exploit]
                        if exploit in secfocus_names
                        else None
                    })

                vuln['_securityfocus'] = None

            else:
                vuln['securityfocus'] = []

                for exploit in vuln['_securityfocus']:
                    vuln['securityfocus'].append({
                        'id': exploit,
                        'title': None
                    })

                vuln['_securityfocus'] = None

            if metasploit_map is not None and vuln['id'] in metasploit_map:
                for expid in metasploit_map[vuln['id']]:
                    vuln['_metasploit'].append(expid)

                vuln['_metasploit'] = set(vuln['_metasploit'])
                vuln['metasploit'] = []

                for exploit in vuln['_metasploit']:
                    vuln['metasploit'].append({
                            'id': exploit,
                            'title': metasploit_names[exploit]
                            if exploit in metasploit_names
                            else None
                        })

                vuln['_metasploit'] = None

            if l337day_map is not None and vuln['id'] in l337day_map:
                for expid in l337day_map[vuln['id']]:
                    vuln['_l337day'].append(expid)

                vuln['_l337day'] = set(vuln['_l337day'])

                vuln['l337day'] = []

                for exploit in vuln['_l337day']:
                    vuln['l337day'].append({
                            'id': exploit,
                            'title': l337day_names[exploit]
                            if exploit in l337day_names
                            else None
                    })

                vuln['_l337day'] = None

            vulns.append(vuln)

    info('Extracted {byellow}{vulncount:,}{rst} vulnerabilites.', vulncount=len(vulns))

    return vulns


def create_db(names, aliases, vulns):
    info('Initiating SQLite creation...')

    if os.path.isfile('db'):
        os.unlink('db')

    conn = sqlite3.connect('db')

    c = conn.cursor()
    c.execute('create table vulns (id integer primary key autoincrement, cve text, date datetime, description text, availability char(1), vendor text)')
    c.execute('create table affected (vuln_id integer not null, cpe text, foreign key(vuln_id) references vulns(id))')
    c.execute('create table aliases (class int, cpe text)')
    c.execute('create table exploits (site int, sid text, cve text, title text)')
    c.execute('create virtual table names using fts4(cpe, name)')

    info('Creating tables {bgreen}vulns{rst}, {bgreen}affected{rst} and {bgreen}exploits{rst}...')

    for vuln in vulns:
        c.execute(
            'insert into vulns (cve, date, description, availability, vendor) values (?, ?, ?, ?, ?)',
            [
                vuln['id'],
                vuln['date'],
                vuln['description'],
                vuln['availability'],
                '\x1e'.join(vuln['vendor']) if vuln['vendor'] else None
            ]
        )

        id = c.lastrowid

        for affected in vuln['affected']:
            c.execute('insert into affected (vuln_id, cpe) values (?, ?)', [id, affected[8:]])

        if 'exploitdb' in vuln:
            for exploit in vuln['exploitdb']:
                c.execute('insert into exploits (site, sid, cve, title) values (?, ?, ?, ?)', [1, exploit['id'], vuln['id'], exploit['title']],)

        if 'securityfocus' in vuln:
            for exploit in vuln['securityfocus']:
                c.execute('insert into exploits (site, sid, cve, title) values (?, ?, ?, ?)', [2, exploit['id'], vuln['id'], exploit['title']])

        if 'metasploit' in vuln:
            for exploit in vuln['metasploit']:
                c.execute('insert into exploits (site, sid, cve, title) values (?, ?, ?, ?)', [5, exploit['id'], vuln['id'], exploit['title']])

        if 'l337day' in vuln:
            for exploit in vuln['l337day']:
                c.execute('insert into exploits (site, sid, cve, title) values (?, ?, ?, ?)', [10, exploit['id'], vuln['id'], exploit['title']])

    info('Creating table {bgreen}names{rst}...')

    for name in names:
        c.execute('insert into names (cpe, name) values (?, ?)', name)

    info('Creating table {bgreen}aliases{rst}...')

    group_counter = 0

    for alias_group in aliases:
        for alias in alias_group:
            c.execute('insert into aliases (class, cpe) values (?, ?)', [group_counter, alias])

        group_counter += 1

    info('Creating indices...')

    c.execute('create index cpe_vuln_idx on affected (cpe collate nocase)')
    c.execute('create index cpe_alias_cpe_idx on aliases (cpe collate nocase)')
    c.execute('create index cpe_alias_class_idx on aliases (class)')
    c.execute('create index cve_exploit_idx on exploits (cve, site)')

    conn.commit()
    conn.close()

    info('Finished database creation.')


def update_db():
    download_nvd_dbs()

    names = parse_cpe_names()
    aliases = parse_cpe_aliases()
    exploits = parse_exploits()
    vulns = parse_cve_items(exploits)

    create_db(names, aliases, vulns)


def fuzzy_find_cpe(name, version=None):
    conn.create_function('bm25', 2, bm25)

    if version is None:
        parts = re.split(r'\bv?(\d+(?:\.\d)?)', name, 1, re.I)

        if len(parts) > 1:
            name = parts[0]

            version = ''.join(parts[1:])

    name = re.sub('\s\s*', ' ', name.lower()).strip()

    if not version:
        query = 'select cpe, name, bm25(matchinfo(names, "pcxnal"), 1) as rank from names where name match ? and rank > 0 order by rank desc limit 10'

        params = [name]

    else:
        query = 'select cpe, name, bm25(matchinfo(names, "pcxnal"), 1) as rank from names where name match ? and name like ? and rank > 0 order by rank desc limit 10'

        params = [name, '%' + version + '%']

    for row in c.execute(query, params):
        return row[0]

    name = name.replace(' ', ' OR ')

    params = [name] if not version else [name, '%' + version + '%']

    for row in c.execute(query, params):
        return row[0]


def get_cpe_aliases(cpe):
    cparts = cpe.split(':')

    cpebase = ':'.join(cparts[:3])
    version = ':'.join(cparts[3:])

    aliases = []

    for row in c.execute('select cpe from aliases where class = (select class from aliases where cpe like ?)', [cpebase]):
        alias = row[0]

        if version:
            alias += ':' + version

        aliases.append(alias)

    return aliases


def get_vulns(cpe):
    vulns = []

    if cpe.startswith('cpe:/'):
        cpe = cpe[5:]

    cparts = cpe.split(':')

    if len(cparts) < 4:
        warn('Name {byellow}cpe:/{cpe}{rst} has no version. Use {bred}-a{rst} to dump all vulnerabilities.')

        return

    aliases = get_cpe_aliases(cpe)

    if aliases:
        query = ''

        params = []

        for alias in aliases:
            query += 'cpe like ? or cpe like ? or '

            params.append(alias)
            params.append(alias + ':%')

        query = query[:-4]

    else:
        query = 'cpe like ? or cpe like ?'

        params = [cpe, cpe + ':%']

    for row in c.execute(f'select cve, cpe, date, description, availability from affected join vulns on vulns.id = affected.vuln_id where {query} order by id desc', params):
        vulns.append(row)

    return vulns


def get_exploits(cves):
    exploits = []

    params = ''

    for cve in cves:
        params += '?, '

    params = params.rstrip(', ')

    for row in c.execute(f'select site, sid, cve, title from exploits where cve in ({params}) order by cve desc, site asc', cves):
        exploits.append(row)

    return exploits


def get_vulns_cli(cpe):
    vulns = get_vulns(cpe)

    if not cpe.startswith('cpe:/'):
        cpe = f'cpe:/{cpe}'

    if vulns is not None and not vulns:
        info('Entry {byellow}{cpe}{rst} has no vulnerabilities.')

        return

    if vulns is None:
        return

    info('Entry {byellow}{cpe}{rst} has the following vulnerabilities:')

    cols = int(os.environ['COLUMNS'])

    cves = []

    for vuln in vulns:
        cves.append(vuln[0])

        color = '{red}' if vuln[4] == 'C' else '{yellow}' if vuln[4] == 'P' else '{crst}'

        descr = vuln[3]

        if len(descr) > cols - 18:
            descr = descr[: cols - 20] + ' >'

        descr = re.sub(
            r'\b(denial.of.service|execute|arbitrary|code|overflow|gain|escalate|privileges?)\b',
            r'{bgreen}\1{rst}',
            descr
        )

        tally('{color}{bright}CVE-{vuln[0]}{rst} {descr}')

    exploits = get_exploits(cves)

    if exploits:
        info('Entry {byellow}{cpe}{rst} has the following public exploits:')

        last_cve = ''
        descr = ''

        for exploit in exploits:
            if last_cve != exploit[2]:
                if last_cve:
                    tally('{bred}CVE-{last_cve}{rst} ' + descr)

                    descr = ''

                last_cve = exploit[2]

            descr += '\n    - '

            if exploit[3] is not None:
                descr += '{bright}' + exploit[3] + '{srst}\n      '

            if exploit[0] == 1:
                descr += 'https://www.exploit-db.com/exploits/' + exploit[1]

            elif exploit[0] == 2:
                descr += 'http://www.securityfocus.com/bid/' + exploit[1] + '/exploit'

            elif exploit[0] == 5:
                descr += 'metasploit ' + exploit[1]

            elif exploit[0] == 10:
                descr += 'http://0day.today/exploit/' + exploit[1]

            else:
                descr += exploit[1]

        tally('{bred}CVE-{last_cve}{rst} {descr}')

    else:
        info('Entry {byellow}{cpe}{rst} has no public exploits.')


def exscan(host):
    options = '-sV'

    nm = NmapProcess(host, options)

    info('Performing nmap scan on {bgreen}{host}{rst}...')

    rc = nm.run()

    if rc:
        fail(f'Nmap scan failed: {nm.stderr}')

    try:
        report = NmapParser.parse(nm.stdout)
    except NmapParserException as e:
        fail(f'Report parse failed: {e}')
    
    info('Processing nmap report...')

    for host in report.hosts:
        for service in host.services:
            msg = 'Service {bgreen}{host.address}{rst}:{bgreen}{service.port}{rst}/{bgreen}{service.protocol}{rst}'

            if service.service_dict.get('cpelist'):
                info(msg + ' is {byellow}' + '{rst}, {byellow}'.join(service.service_dict['cpelist']) + '{rst}')

                for cpe in service.service_dict['cpelist']:
                    get_vulns_cli(cpe)

            elif service.service_dict.get('product'):
                product = service.service_dict.get('product', '')
                version = service.service_dict.get('version', '')
                extrainfo = service.service_dict.get('extrainfo', '')

                full = f'{product} {version} {extrainfo}'.strip()

                cpe = fuzzy_find_cpe(f'{product} {extrainfo}', version)

                if cpe is None:
                    warn(msg + ' was identified as {bred}{full}{rst} with no matching CPE name.')

                else:
                    info(msg + ' was identified as {bred}{full}{rst} and fuzzy-matched to {byellow}cpe:/' + cpe + '{rst}.')

                    get_vulns_cli(cpe)

            else:
                warn(f'{msg} wasnt identified.')


if not os.path.isfile('db'):
    update_db()

conn = sqlite3.connect('db')

c = conn.cursor()


def check_host(host):
    try:
        ip = ipaddress.ip_address(host)
        
        return True
    except ValueError:
        return False


try:
	cprint('{byellow}Vit{bred}sploit{rst}\n', mark=None)

	target = input(f'{Style.BRIGHT}{Fore.RED}Target IP:{Fore.RESET} ')

	if check_host(target):
		ws = WebScan()
		ws.scan_host(target)

		exscan(target)

	else:
		fail('Invalid IP.')
except KeyboardInterrupt:
	pass
