#!/var/ossec/framework/python/bin/python3
##### get_all_packages.py
# Author: Juan C. Tello
# Version: 2021.12.09
# Description:
#   This script will collect packages of all agents through the Wazuh manager's
#   framework and send them to the Analysisd socket to allow alerts to be generated.
#
# Configuration:
#   You may run this periodically on the Wazuh manager by using a command wodle:
#
#   <wodle name="command">
#     <disabled>no</disabled>
#     <command>path/get_all_packages.py</command>
#     <interval>24h</interval>
#     <ignore_output>yes</ignore_output>
#     <run_on_start>yes</run_on_start>
#     <timeout>0</timeout>
#   </wodle>
# 
# Example rule:
# <group name="syscollector_packages">
#  
#    <rule id="103100" level="0">
#      <location>syscollector_packages</location>
#      <description>get_all_packages.py parent rule</description>
#    </rule>
#    
#    <rule id="103101" level="3">
#      <if_sid>103100</if_sid>
#      <options>no_full_log</options>
#      <field name="package.name">^python$</field>
#      <field name="package.version">^2</field>
#      <description>Python 2 is installed</description>
#    </rule>
#  
#  </group>

from wazuh import syscollector
from socket import socket, AF_UNIX, SOCK_DGRAM

# Wazuh manager analisysd socket address
socketAddr = '/var/ossec/queue/sockets/queue'

# Send event to Wazuh manager
def send_event(msg):
    string = '1:syscollector_packages:{}'.format(msg)
    sock = socket(AF_UNIX, SOCK_DGRAM)
    sock.connect(socketAddr)
    sock.send(string.encode())
    sock.close()

agents = syscollector.get_agents_info()
for a in agents:
    packages = syscollector.get_item_agent(agent_list=a,element_type='packages')
    for p in packages.to_dict()['affected_items']:
        send_event('{"agent":"'+a+'","package":{"name":"'+p["name"]+'","version":"'+p["version"]+'"}}')

