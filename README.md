# JCT-Wazuh
I've created this repository to share tools I've created for enhancing, troubleshooting and integrating Wazuh.
This is not meant to be a library but a lose collection of scripts so functions may be redundant to allow for easier granular implementation depending on the needs of each environment.

Feel free to use any of them on your own projects.

## Contents

There are a few categories in this repository. Note that some of these tools may become obsolete as their functionality may be provided natively by Wazuh in the future.

### Wodles
Wodles are commands that are periodically executed to retrieve information from an external source.  
Funny undocumented anecdote:  "wodle" was chosen as a portmanteau of Wazuh and Module.

#### get_all_packages.py
This wodle will allow users to periodically query the list of packages installed on all agents and generate an alert when specific packages are found to be installed. For example, to alert if Python 2 is still present in the system.

#### esquery.py
This wodle is meant to periodically query events indexed in Elasticsearch (or equivalent) for Wazuh events. This will allow you to determine, for example, if a specific source has stopped reporting events recently.

### Integrations
Integrations are extensions that can be executed on the Wazuh manager in response to a event and use information from that event.

#### custom-email-alerts
This integration allows the user to send fully customizable email alerts for events observed by the Wazuh manager. This was created to overcome the limitations of the hard coded mail daemon built into Wazuh.


### Tools
This section is reserved for tools that are not executed directly by Wazuh but allow us to expand its functionalities, troubleshoot or configure it.

#### CEF & LEEF automatic decoder creators
These utilities will allow you to automatically create sibling decoders for logs that are written using either the LEEF or CEF log formats. 
