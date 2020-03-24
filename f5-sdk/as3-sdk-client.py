#!/usr/bin/env python

# Replicate
# as3-client.py --host bigip.aws.example.com:8443 -f python/virtualservice/AS3/templates/https_waf_sd_aws.json --sd-tag-key aws:autoscaling:groupName --sd-tag-value ${#stage(\"Deploy in us-west-2\").context[\"deploy.server.groups\"][\"us-west-2\"]} -a deploy

# Usage: as3-client.py --host XX.XX.XX.XX --port 8443  -f templates/https_waf_sd_aws.json.j2 --runtime-vars 'tagKey=aws:autoscaling:groupName,tagValue=f5demoapp-prod-v004,region=us-west-2'

""" Update BIG-IP L4-L7 configuration using AS3

Notes
-----
Set local environment variables first
"""

#import jsonpatch
import argparse
import json
import os
import sys
import logging
from jinja2 import Template

from f5sdk.bigip import ManagementClient
from f5sdk.bigip.extension import ExtensionClient
from f5sdk.logger import Logger

LOGGER = Logger(__name__).get_logger()

if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='Script to manage an AS3 declaration')
    parser.add_argument("--host", help="The IP/Hostname of the BIG-IP device",default='https://192.168.1.245')
    parser.add_argument("--port", help="The MGMT Port BIG-IP device",default='443')
    parser.add_argument("-u", "--username",default='admin')
    parser.add_argument("-p", "--password",default='admin')

    parser.add_argument("-f","--file",help="declaration JSON file")
    parser.add_argument("--runtime-vars",dest="runtime_vars",help="comma seperated list of run time vars. ex. tagKey=myvalue1,tagValue=myvalue1, ")

    parser.add_argument("--level",help="log level (default info)",default="info")
    parser.add_argument("--show",help="show")

    args = parser.parse_args()

    username = args.username
    password = args.password
    host = args.host
    port = args.port
    declaration_template = open(args.file).read()
    runtime_vars_d = dict(x.split("=") for x in args.runtime_vars.split(","))

    if 'F5_USERNAME' in os.environ:
        username = os.environ['F5_USERNAME']

    if 'F5_PASSWORD' in os.environ:
        password = os.environ['F5_PASSWORD']   

    mgmt_client = ManagementClient( host=host, port=port, user=username, password=password )

    # # create extension client
    as3_client = ExtensionClient(mgmt_client, 'as3')

    # # Get installed package version info
    version_info = as3_client.package.is_installed()
    LOGGER.info(version_info['installed'])
    LOGGER.info(version_info['installed_version'])
    LOGGER.info(version_info['latest_version'])

    # # install package
    if not version_info['installed']:
       as3_client.package.install()

    # # ensure service is available
    as3_client.service.is_available()

    # Set payload
    tm = Template(declaration_template)    
    rendered = tm.render(runtime_vars_d)

    # # configure AS3
    result = as3_client.service.create(config=json.loads(rendered))
    #result = as3_client.service.create(config=payload)
    print(json.dumps(result, indent=2))

