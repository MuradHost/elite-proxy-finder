#!/usr/bin/env python2

'''Finds hundreds of elite anonymity (L1) HTTP proxies then tests them all in parallel printing the fastest ones first.
Checks headers to confirm eliteness, checks if compatible with opening HTTPS sites, and confirms the proxy is working
through multiple IP checking sites'''

# TO DO:
# -Add http://free-proxy-list.net/
# -Add hidemyass
#from IPython import embed

__author__ = 'Dan McInerney'
__contact__ = 'danhmcinerney gmail'

from gevent import monkey
monkey.patch_all()
#"7061756c".decode("hex")
import requests
import ast
import gevent
import sys, re, time, os, argparse
import socket
from BeautifulSoup import BeautifulSoup

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-s', '--show', help='Show this number of results. Example: "-s 5" will show the 5 fastest proxies then stop')
    parser.add_argument('-a', '--all', help='Show all proxy results including the ones that failed 1 of the 3 tests', action='store_true')
    parser.add_argument('-q', '--quiet', help='Only print the IP:port of the fastest proxies that pass all the tests', action='store_true')
    return parser.parse_args()

class find_http_proxy():
    ''' Will only gather L1 (elite anonymity) proxies
    which should not give out your IP or advertise
    that you are using a proxy at all '''

    def __init__(self, args):
        self.proxy_list = []
        self.headers = {'User-Agent':'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/33.0.1750.154 Safari/537.36'}
        self.show_num = args.show
        self.show_all = args.all
        self.quiet = args.quiet
        self.errors = []
        self.print_counter = 0
        self.externalip = self.external_ip()

    def external_ip(self):
        req = requests.get('http://myip.dnsdynamic.org/', headers=self.headers)
        ip = req.text
        return ip

    def run(self):
        ''' Gets raw high anonymity (L1) proxy data then calls make_proxy_list()
        Currently parses data from gatherproxy.com and letushide.com '''


         # Has a login now :(
        gatherproxy_list = self.gatherproxy_req()
        if not self.quiet:
            print '[*] gatherproxy.com: %s proxies' % str(len(gatherproxy_list))




        self.proxy_list.append(gatherproxy_list)


        # Flatten list of lists (1 master list containing 1 list of ips per proxy website)
        self.proxy_list = [ips for proxy_site in self.proxy_list for ips in proxy_site]
        self.proxy_list = list(set(self.proxy_list)) # Remove duplicates

        if not self.quiet:
            print '[*] %d unique high anonymity proxies found' % len(self.proxy_list)
            print '[*] Testing proxy speeds ...'
            print ''
            print '      Proxy           | CC  |       Domain          | Time/Errors'

        self.proxy_checker()









    def gatherproxy_req(self):
        url = 'http://gatherproxy.com/proxylist/anonymity/?t=Elite'
        try:
            r = requests.get(url, headers = self.headers)
            lines = r.text.splitlines()
        except:
            print '[!] Failed get reply from %s' % url
            gatherproxy_list = []
            return gatherproxy_list

        gatherproxy_list = self.parse_gp(lines)
        return gatherproxy_list

    def parse_gp(self, lines):
        ''' Parse the raw scraped data '''
        gatherproxy_list = []
        for l in lines:
            if 'proxy_ip' in l.lower():
                l = l.replace('gp.insertPrx(', '')
                l = l.replace(');', '')
                l = l.replace('null', 'None')
                l = l.strip()
                l = ast.literal_eval(l)
                xhm = int(l["PROXY_PORT"], 16)
                proxy = '%s:%s' % (l["PROXY_IP"], str(xhm))
                #"7061756c".decode("hex")

                gatherproxy_list.append(proxy)
                #ctry = l["PROXY_COUNTRY"]
        return gatherproxy_list

    def proxy_checker(self):
        ''' Concurrency stuff here '''
        jobs = [gevent.spawn(self.proxy_checker_req, proxy) for proxy in self.proxy_list]
        try:
            gevent.joinall(jobs)
        except KeyboardInterrupt:
            sys.exit('[-] Ctrl-C caught, exiting')

    def proxy_checker_req(self, proxy):
        ''' See how long each proxy takes to open each URL '''
        proxyip = str(proxy.split(':', 1)[0])

        # A lot of proxy checker sites give a different final octet for some reason
        #proxy_split = proxyip.split('.')
        #first_3_octets = '.'.join(proxy_split[:3])+'.'

        results = []
        urls = ['http://myip.dnsdynamic.org']
        for url in urls:
            try:
                check = requests.get(url,
                                    headers = self.headers,
                                    proxies = {'http':'http://'+proxy,
                                               'https':'http://'+proxy},
                                    timeout = 15)

                time_or_error = str(check.elapsed)
                html = check.text
                time_or_error = self.html_handler(time_or_error, html, url)
                url = self.url_shortener(url)
                results.append((time_or_error, proxy, url))

            except Exception as e:
                time_or_error = self.error_handler(str(e))
                url = self.url_shortener(url)
                results.append((time_or_error, proxy, url))

        self.print_handler(results, proxyip)

    def html_handler(self, time_or_error, html, url):
        ''' Check the html for errors and if none are found return time to load page '''

        html_lines = html.splitlines()
        leng = len(html_lines)
        ipre = '(?:[0-9]{1,3}\.){3}[0-9]{1,3}'

        # Both of these urls just return the ip and nothing else
        if url in ['http://danmcinerney.org/ip.php', 'http://myip.dnsdynamic.org']:
            if leng == 1:  # Should return 1 line of html
                match = re.match(ipre, html)
                if match:
                    if self.externalip in html:
                        time_or_error = 'Err: Page loaded; proxy failed'
                else:
                    time_or_error = 'Err: Page loaded; proxy failed'
            else:
                time_or_error = 'Err: Page loaded; proxy failed'
            return time_or_error

        # This is the SSL page
        if 'astrill' in url:
            soup = BeautifulSoup(html)
            ip = soup.find("td", { "colspan": 2 }).text # the ip is the only on with colspan = 2
            match = re.match(ipre, ip)
            if match:
                if self.externalip in ip:
                    time_or_error = 'Err: Page loaded; proxy failed'
            else:
                time_or_error = 'Err: Page loaded; proxy failed'
            return time_or_error

        if '/headers' in url:
            # check for proxy headers
            proxy_headers = ['via: ', 'forwarded: ', 'x-forwarded-for', 'client-ip']
            if leng > 15: # 15 is arbitrary, I just don't think you'll ever see more than 15 headers
                time_or_error = 'Err: headers not returned'
                return time_or_error
            for l in html_lines:
                for h in proxy_headers:
                    if h in l.lower():
                        time_or_error = 'Err: Proxy headers found'
                        return time_or_error
            time_or_error = 'Passed: elite proxy'
            return time_or_error

    def print_handler(self, results, proxyip):
        if self.show_all:
            country_code = self.get_country_code(proxyip)
            self.printer(results, country_code)
            self.print_counter += 1
        else:
            passed_all = self.passed_all_tests(results)
            if passed_all:
                country_code = self.get_country_code(proxyip)
                self.printer(results, country_code)
                self.print_counter += 1

        if self.show_num:
            self.limiter()

    def printer(self, results, country_code):
        ''' Creates the output '''
        counter = 0
        if not self.quiet:
            print '--------------------------------------------------------------------'
        for r in results:
            counter += 1
            time_or_error = r[0]
            proxy = r[1]
            url = r[2]

            if self.quiet:
                if counter % 4 == 0: #################### THIS results is a list of 4 tuples each, so proxies will repeat 4 times
                    print proxy
            else:
                # Only print the proxy once, on the second print job
                if counter == 1:
                    print '%s | %s | %s | %s' % (proxy.ljust(21), country_code.ljust(3), url.ljust(21), time_or_error)
                else:
                    print '%s | %s | %s | %s' % (' '.ljust(21), '   ', url.ljust(21), time_or_error)

    def get_country_code(self, proxyip):
        ''' Get the 3 letter country code of the proxy using geoiptool.com
        Would use the geoip library, but it requires a local DB and what
        is the point of that hassle other than marginal speed improvement '''
        cc_line_found = False
        cc = 'N/A'

        try:
            r = requests.get('http://who.is/whois-ip/ip-address/%s' % proxyip, headers=self.headers)
            html = r.text
            html_lines = html.splitlines()
            for l in html_lines:

                if 'country:' in l:
                    cc_line_found = True
                    l=l.replace(" ", "")
                    l=l.replace("country:", "")
                    cc=l
                    break

        except NameError :
         pass

        return cc

    def error_handler(self, e):
        if 'Cannot connect' in e:
            time_or_error = 'Err: Cannot connect to proxy'
        elif 'timed out' in e.lower():
            time_or_error = 'Err: Timed out'
        elif 'retries exceeded' in e:
            time_or_error = 'Err: Max retries exceeded'
        elif 'Connection reset by peer' in e:
            time_or_error = 'Err: Connection reset by peer'
        elif 'readline() takes exactly 1 argument (2 given)' in e:
            time_or_error = 'Err: SSL error'
        else:
            time_or_error = 'Err: ' + e
        return time_or_error

    def url_shortener(self, url):
        if 'ip.php' in url:
            url = 'danmcinerney.org'
        elif 'headers.php' in url:
            url = 'Header check'
        elif 'dnsdynamic' in url:
            url = 'dnsdynamic.org'
        elif 'astrill' in url:
            url = 'https://astrill.com'
        return url

    def passed_all_tests(self, results):
        for r in results:
            time_or_error= r[0]
            if 'Err:' in time_or_error:
                return False
        return True

    def limiter(self):
        ''' Kill the script if user supplied limit of successful proxy attempts (-s argument) is reached '''
        if self.print_counter >= int(self.show_num):
            sys.exit()

P = find_http_proxy(parse_args())
P.run()
