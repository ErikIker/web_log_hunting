#!/usr/bin/env python
# written by Erik Iker - @ ErikIkerFW
# Purpose is to perform triage on IIS logs to get a set of IP address
# to focus on for potential web shell activity based on POST without referer
# and 90% of POST to GET traffic ratio
# Also tries to triage for other web attacks 
# based upon multiple failure codes before success status codes
from __future__ import print_function

from argparse import ArgumentParser
import codecs
from collections import Counter
import datetime
from glob import iglob
import os
import re
import time


date_time = datetime.datetime.now().strftime("%Y%m%d-%H%M")
# Ordered Dictionary to hold status code in order they were added so
# that it can be sequentially checked for failure or success codes later
status_code_dict = {}
# Dictionary to hold IP, method and referrer data to process for POST
# and get ratios relevant to potential webshell activity
webshell_dict = {}
# regular expression for only validated ip addresses
ip_line = re.compile('^(.*?)((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
                     '(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)')
method_line = re.compile('^(.*?)(GET|POST|HEAD|CONNECT|PUT|DELETE|OPTIONS)')

# Regular expression to capture each field from base IIS log file line
iis_log = re.compile(
    r'(?P<date>\d+\-\d+\-\d+) (?P<dt>\d{2}\:\d{2}\:\d{2}) (?P<site>.*?) '
    '(?P<server>.*?) (?P<s_ip>\d+\.\d+\.\d+\.\d+) (?P<method>.*?) '
    '(?P<uri_stem>.*?) (?P<uri>.*?) (?P<d_port>\d+) (?P<username>.*?) '
    '(?P<c_ip>\d+\.\d+\.\d+\.\d+) (?P<http_version>.*?) (?P<user_agent>.*?) '
    '(?P<cookie>.*?) (?P<referrer>.*?) (?P<host>.*?) (?P<status_code>\d+) '
    '(?P<sc_bytes>\d+) (?P<cs_bytes>\d+) (?P<time_taken>\d+)'
)


def build_dict(path, filename_pattern):
    """
    Takes all files ending in 'log' in the path given and evaluates them
    as Apache access.log files, splitting on the identifiers around the IP addr
    and request method to strip the text around those elements and add to a
    dictionary with the key being the IP and all methods the values of the dict

    """
    search_path = os.path.join(path, filename_pattern)
    start = time.time()
    count = 0
    for count, filename in enumerate(iglob(search_path), start=1):
        print('Now processing #{:,}: {}'.format(count, filename))
        with codecs.open(filename, encoding='utf-8',
                         errors='replace') as infile:
            for line_no, line in enumerate(infile):
                if line.startswith('#'):
                    continue
                match = re.match(iis_log, line)
                if match:
                    date, dt, site, server, s_ip, method, uri_stem, \
                        uri, port, username, ip, http_version, user_agent, \
                        cookie, referrer, host, status_code, sc_bytes, \
                        cs_bytes, time_taken = \
                        match.groups()
                    status_code_processing(ip, status_code)
                    iis_method_processing(ip, method, referrer)
                else:
                    pass
    # If there are no valid files in the path, end the function
    if count == 0:
        return
    stop = time.time()
    # Alert user and quit if no files were processed.
    print('Processed {:,} files in {:.3} seconds'.format(count, stop - start))

    return webshell_dict


def report_writer(path):
    """
    Takes dictionaries produced from log processing and output results.
    Dictionaries are global variables currently. Will be passed from
    another function where dictionaries are produced in a later state.
    Webshell results file is only the IP addresses of interest to be used
    to gather further data of interest through "user grep -f" commands
    """

    ws_results_file = ('webshell_triage_results' + str(date_time) + '_.txt')
    sc_results_file = ('status_code_triage_results' + str(date_time) + '_.txt')
    with codecs.open(ws_results_file, encoding='utf-8', mode='w',
                     errors='replace') as ws_output:
        print('"Writing webshell results to ' + ws_results_file + '"')
        # iterate through all keys and values in the dictionary of
        # methods and IPs to look for > 10:1 POST to GET value ratio
        for k, v in webshell_dict.iteritems():
            # Count all the values in the dictionary
            v = Counter(v)
            # count instances of POST and GET so they can be compared
            post_count = v['POST']
            get_count = v['GET']
            # To reduce false negatives, instead of just POST only entries
            # return all values with more than 90% POST methods
            if (get_count / post_count) < .1:
                print (k + ' | is an IP of interest with ' + str(post_count) +
                       ' POSTs and ' + str(get_count) + ' GETs')
                ws_output.write(k + '\n')
    with codecs.open(sc_results_file, encoding='utf-8', mode='w',
                     errors='replace') as sc_output:
        print('"Writing webshell results to ' + sc_results_file + '"')
        for k, v in status_code_dict.iteritems():
            vcounter = 0
            for i in v:
                if vcounter > 7 and int(i) < 399:
                    print (k + " has status code anomalies of interest")
                    sc_output.write(k + str(v))
                    break
                if int(i) > 399:
                    vcounter += 1
                if int(i) < 399:
                    vcounter = 0


def status_code_processing(ip, status_code):
    """
    Receives ip and status code from log parsing function for evaluation
    New IP addresses are added to the orderedDict if there is a failure status
    of a 4## or 5## code. If the ip address is already a key then additional
    status codes are added so that it can be evaluated if multiple failures
    occur before success. Looking for recon of dir traveral, SQLi etc

    """
    if ip in status_code_dict:
        status_code_dict[ip].append(status_code)
    elif int(status_code) > 399:
        status_code_dict[ip] = []
        status_code_dict[ip].append(status_code)
    return status_code_dict


def iis_method_processing(ip, method, referrer):
    """
    Receives ip, method, and referrer from log parsing function for evaluation
    IP address is added to the dictionary once it has an entry with
    a POST method and no referer.  once an IP is added to the dict
    all additional methods are added for that IP so it can be
    evalutated if more than 90% of traffic is POST

    """
    # for test file I want less restrictive so commenting out temporarily
    if ip in webshell_dict:
        webshell_dict[ip].append(method)
        webshell_dict[ip].append(referrer)
    elif ((method == 'POST') and (len(referrer) < 2)):
        webshell_dict[ip] = []
        webshell_dict[ip].append(method)
        webshell_dict[ip].append(referrer)
    else:
        pass


def common_method_processing(ip, method):
    """
    Receives ip and method from log parsing function for evaluation
    IP address is added to the dictionary once it has an entry with 
    a POST method.  The common log format does not have a referer
    Once an IP is added to the dict all additional methods are
    added for that IP to evalutate if more than 90% of traffic is POST

    """
    if ip in webshell_dict:
        webshell_dict[ip].append(method)
    elif method == 'POST':
        webshell_dict[ip] = []
        webshell_dict[ip].append(method)
    else:
        pass


def main():
    # Parse command line arguments
    ap = ArgumentParser()
    ap.add_argument(
        'path',
        help='A valid path to be searched for *.log files'
    )
    ap.add_argument(
        '-fp',
        '--filename-pattern',
        type=str,
        default='*.log',
        help='The pattern (glob) to identify log files ("*.log")'
    )
    args = ap.parse_args()

    # Get the real, normal path.
    path = os.path.realpath(os.path.normpath(args.path))

    # Confirm the path is valid.  If not, show the user exactly what they entered.
    if not os.path.isdir(path):
        print('The path you provided, "{}", is invalid.'.format(args.path))
        return

    # Process
    build_dict(path, args.filename_pattern)
    report_writer(path)

if __name__ == '__main__':
    main()
