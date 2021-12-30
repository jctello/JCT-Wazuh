#!/var/ossec/framework/python/bin/python3
################# LEEF-automatic-decoder-creator.py ###########################
#                                                                             #
#  Utility to automatically create decoders for LEEF formatted logs           #
#  Usage: python LEEF-automatic-decoder-creator.py SampleLogFiles*            #
#  This will extract all fields and create sibling decoders thus allowing     #
#  Wazuh to extract all fields observed.                                      #
#                                                                             #
#  This utility has also been adapted to the CEF-automatic-decoder-creator.py #
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
       fields = re.findall(r"\t(.*?)=",l)
       for i in fields:
           if i not in AllFields:
               AllFields.append(i)

print('Total fields: {}'.format(len(AllFields)))
print(sorted(AllFields))

outfile = open('LEEF_decoders.xml','w')

outfile.write("""
<decoder name="LEEF">
  <prematch>LEEF:\.*\|\.*\|\.*\|\.*\|\.*\|</prematch>
</decoder>

<decoder name="LEEF">
  <parent>LEEF</parent>
  <regex>LEEF:(\.*)\|(\.*)\|(\.*)\|(\.*)\|(\.*)\|</regex>
  <order>LEEFversion,Vendor,Product,ProductVersion,EventID</order>
</decoder>
""")

for field in sorted(AllFields):
    outfile.write("""
<decoder name="LEEF">
  <parent>LEEF</parent>
  <regex>{0}=(\.*)\\t|{0}=(\.*)$</regex>
  <order>{0}</order>
</decoder>

    """.format(field))
# This regex will match anything before a tab or end of line

outfile.close()
