#!/usr/bin/python
# webshell apache log triage - written by Erik Iker - @ErikIkerFW
# script to look for IP addresses with only POST and no GET traffic
# as a means to triage narrow down on potential webshell traffic
# To-Do - extend functionality for scooring of traffic that also has no referer

import os
import codecs
import datetime
import re
time = datetime.datetime.now().strftime("%Y%m%d-%H%M")
ip_line = re.compile('^(.*?)((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
                     '(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)')
method_line = re.compile('^(.*?)(GET|POST|HEAD|CONNECT|PUT|DELETE|OPTIONS)')
# Function to get path of logs for parsing
def get_path():
    """
    This function is to get the path for the access logs
    and validate that it is a true path
    Args:
    None
    Returns:
    string containing path of the access logs
    """
    path = raw_input('Enter the path of the logs:')
    if os.path.isdir(os.path.normpath(path)):
        return path
    else:
        print('The path "{}" does not exist.'.format(path))
    return path

def build_method_dict(path):
    """
    Takes all files ending in 'log' in the path given and evaluates them
    as Apache access.log files, splitting on the identifiers around the IP addr
    and request method to strip the text around those elements and add to a
    dictionary with the key being the IP and all methods the values of the dict

    """

    # local dictionary to hold IP addr and method for processing
    method_dict = {}
    for filename in os.listdir(path):
        if filename.lower().endswith('log'):
            print('Now processing: ' + filename)
            with codecs.open(path + '//' + os.sep + filename,
                             encoding='utf-8', errors='replace') as file:
    # read first line to get the count of spaces before req IP and method
    # so that the spaces can be counted to make a dynamic split for text
    # in remainder of each log file to reduce errors across different format configs
                header = file.readline()
                if '://' in header is False:
                    continue
                header = file.readline()
                i_split = re.match(ip_line, header)
                i_split = i_split.group(0)
                i_count = i_split.count(' ')
                m_split = re.match(method_line, header)
                m_split = m_split.group(0)
                m_count = m_split.count(' ')
    # read each line and obtain IP address and method to add to dictionary
                for line in file:
    # error catching so line splitting not attempted on any invalid lines
                    if '://' in line:
                        ip = line.split(' ')[i_count]
                        ip = ip.lstrip()
                        ip = ip.split(' ')[0]
                        method = line.split(' ')[m_count]
                        method = method.split(' ')[0]
                        method = method.strip('"')
                        # create new kv pair if ip addr is not in dictionary
                        if ip not in method_dict:
                            method_dict[ip] = []
                            method_dict[ip].append(method)
                        else:
                            method_dict[ip].append(method)
                    else:
                        continue
        #else:
            #print ('No files ending in ".log" are present in the specified path')

    results_file = ('post_only_methods_' + str(time) + '_.txt')
    with codecs.open(results_file, encoding='utf-8', mode='w', errors='replace') as outfile:
        print ('Writing results to ' + (results_file))
        #iterate through all keys and values in the dictionary and if there are only POST
        #methods and no GET methods for any requesting IP addrs, write those to a results file
        for k, v in method_dict.iteritems():
            if 'POST' in v:
                if 'GET' in v:
                    continue
                else:
                    print(k + '| is an IP of interest and will be included in results file.')
                    outfile.write(k + '\n')


path = get_path()
build_method_dict(path)
