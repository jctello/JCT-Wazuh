#!/var/ossec/framework/python/bin/python3
################# CEF-automatic-decoder-creator.py ############################
#                                                                             #
#  Utility to automatically create decoders for CEF formatted logs            #
#  Usage: python CEF-automatic-decoder-creator.py SampleLogFiles*             #
#  This will extract all fields and create sibling decoders thus allowing     #
#  Wazuh to extract all fields observed.                                      #
#                                                                             #
#  This utility has been adapted from the LEEF-automatic-decoder-creator.py   #
#  Considering the fact that CEF uses space separation instead of tabs        #
#                                                                             #
#  Author: Juan Carlos Tello                                                  #
#                                                                             #
###############################################################################

import argparse, re

parser = argparse.ArgumentParser()
parser.add_argument('inputfiles', nargs='+', help="log files from which to extract fields")
args = parser.parse_args()

AllFields = []

for f in args.inputfiles:
   inputlines = open(f,'r').readlines()
   for l in inputlines:
       fields = re.findall(r"(\w*?)=",l)
       for i in fields:
           if i not in AllFields:
               AllFields.append(i)

print('Total fields: {}'.format(len(AllFields)))
print(sorted(AllFields))

outfile = open('CEF_decoders.xml','w')

# The CEF format is:
# Jan 11 10:25:39 host CEF:Version|Device Vendor|Device Product|Device Version|Device Event Class ID|Name|Severity|[Extension]

outfile.write("""
<decoder name="CEF">
  <program_name>CEF</program_name>
</decoder>
<decoder name="CEF">
  <parent>CEF</parent>
  <regex>^(\d+)\|(\.*)\|(\.*)\|(\.*)\|(\.*)\|(\.*)\|(\.*)\|</regex>
  <order>CEFversion,Vendor,Product,ProductVersion,EventID,EventName,EventSeverity</order>
</decoder>
""")

for field in sorted(AllFields):
    outfile.write("""
<decoder name="CEF">
  <parent>CEF</parent>
  <regex>{0}=(\.*)\s\w+=|{0}=(\.*)$</regex>
  <order>{0}</order>
</decoder>
    """.format(field))
# This regex will match anything before a tab or end of line

outfile.close()
