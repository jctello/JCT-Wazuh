#!/var/ossec/framework/python/bin/python3
##### get_all_packages.py
# Author: Juan C. Tello
# Version: 2021.12.30
# Description:
#
# Configuration example:
#
# <wodle name="command">
#   <disabled>no</disabled>
#   <command>/var/ossec/wodles/esquery.py -t 'now-1d/d' -m '{"rule.group":"fortigate"}'</command>
#   <interval>60m</interval>
#   <ignore_output>yes</ignore_output>
#   <run_on_start>yes</run_on_start>
#   <timeout>0</timeout>
# </wodle>
# 
# Example rule:
#  <rule id="100002" level="0">
#    <location>ES_query</location>
#    <description>ESquery returned hits for rule group fortigate</description>
#  </rule>
#
#  <rule id="100003" level="5">
#    <if_sid>100002</if_sid>
#    <match>Event query on Elasticsearch returned 0 hits</match>
#    <description>ESquery returned 0 hits for rule group fortigate</description>
#  </rule>
#############################

import requests
import yaml
import json
import argparse
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning) #No easy way to verify cert without hostname
from socket import socket, AF_UNIX, SOCK_DGRAM

def readEScreds():
    """
    This function reads the filebeat configuration file that is expected to be
    present in any Wazuh manager installation and uses the url and credentials
    stored there to facilitate the querying of the Elasticsearch data.

    As a first iteration it follows the conventions in
     - https://github.com/wazuh/wazuh-packages/blob/v4.2.5/unattended_scripts/open-distro/filebeat/7.x/filebeat_all_in_one.yml
     - https://github.com/wazuh/wazuh-packages/blob/v4.2.5/unattended_scripts/open-distro/filebeat/7.x/filebeat_elastic_cluster.yml
    """
    filebeat_config = yaml.safe_load(open('/etc/filebeat/filebeat.yml'))
    protocol = filebeat_config['output.elasticsearch']['protocol']
    try: host = filebeat_config['output.elasticsearch']['hosts'][0]
    except KeyError: host = filebeat_config['output.elasticsearch.hosts'][0] #unatteded installation required this
    user = filebeat_config['output.elasticsearch']['username']
    pw = filebeat_config['output.elasticsearch']['password']
    cert = filebeat_config['output.elasticsearch']['ssl.certificate']
    url = protocol+'://'+host
    creds = {'url':url,'user':user,'pw':pw,'cert':cert}
    return creds

def queryES(creds,endpoint='wazuh-alerts-*/_search',body=False):
    """
    Function to query the wazuh alerts indexed in Elasticsearch
    If the body is empty it will return the most recent events
    Otherwise the body must be a valid Elasticsearch query as a dict type object
    """
    url = creds['url']+'/'+endpoint
    headers = {'Content-Type': "application/json", 'Accept': "application/json"}
    s = requests.Session()
    s.auth = (creds['user'],creds['pw'])
    r = s.get(url, verify=False,data=body,headers=headers)
    return r

def send_event(msg):
    socketAddr = '/var/ossec/queue/sockets/queue' # for Wazuh <4.2.0 this path is /var/ossec/queue/ossec/queue
    string = '1:ES_query:{}'.format(msg)
    sock = socket(AF_UNIX, SOCK_DGRAM)
    sock.connect(socketAddr)
    sock.send(string.encode())
    sock.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-t','--time',help="Time range for query",default="now-1d/d")
    parser.add_argument('-m','--match',help="match_phrase filter as a json string",default='{"rule.groups":"fortigate"}')
    args = parser.parse_args()
    creds = readEScreds()
    query={"query":{"bool": {"must": [{"match_phrase": json.loads(args.match)}],"filter": {"range": {"timestamp":{"gte":args.time}}}}}} # This looks for events from the "fortigate" group in the last 24 hours
    response = queryES(creds,endpoint='wazuh-alerts-*/_search',body=json.dumps(query))
    hits = json.loads(response.text)['hits']['total']['value']
    send_event('Event query on Elasticsearch returned {} hits'.format(hits))
