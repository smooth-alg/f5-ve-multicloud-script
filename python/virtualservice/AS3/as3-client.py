#!/usr/bin/env python

#################################################
#  Originally Written by e.chen@f5.com          #
#  Borrowed/Modified by a.applebaum@f5.com      #
#################################################

from icontrol.session import iControlRESTSession
from icontrol.exceptions import iControlUnexpectedHTTPError
from requests.exceptions import HTTPError
#import jsonpatch
import argparse
import json
import os
import sys
import logging

if sys.version_info[0] > 2:
    raw_input = input

MIN_PAYLOAD = """{
  "class": "ADC",
  "schemaVersion": "3.0.0",
  "id":"mystub",
  "%s": {
    "class": "Tenant",
    "minimalApp": {
      "class": "Application",
      "template": "http",
      "serviceMain": {
        "class": "Service_HTTP",
        "virtualAddresses": [
          "198.19.193.17"
        ],
        "virtualPort": 2612
      }
    }
}
}"""

class AS3(object):

    def __init__(self, 
                 host="192.168.1.245", 
                 username="admin", 
                 password="admin",
                 token=None,
                 sync_group=None,
                 log_level="info",
                 trace=False,
                 persist=False):

        self._username = username
        self._password = password

        if "http" not in host:
            self.base_url = "https://%s/mgmt" %(host)
        else:
            self.base_url = host

        self.sync_group = sync_group
        self.log_level = log_level
        self.trace = trace
        self.persist = persist

        if token:
            self.icr = iControlRESTSession(username, password, token='tmos')
        else:
            self.icr = iControlRESTSession(username, password)


    def get(self,tenant=None):

        if tenant:
            req = self._get("/shared/appsvcs/declare/" + tenant)
        else:
            req = self._get("/shared/appsvcs/declare")

        return req

    def _get(self,uri):
        try:
            return self.icr.get(self.base_url + uri)
        except HTTPError as exc:
            # override icontrol 404 error
            if exc.response.status_code == 404:
                return exc.response
            else:
                raise
    def _post(self, uri, data, headers=None):

        return self.icr.post(self.base_url + uri,data=data,headers=headers)


    def post(self, payload):
        try:
            req = self._post("/shared/appsvcs/declare",data=json.dumps(payload))
        except HTTPError as exc:
            # override icontrol errors
            return exc.response
        return req


    def deploy(self, payload):
        payload = self._set_action(payload, "deploy")
        tenants = set(payload['declaration'].keys())
        tenants = list(tenants - set(['schemaVersion','class','id','remark','controls','label']))
        try:
            req = self._post("/shared/appsvcs/declare",data=json.dumps(payload))
        except HTTPError as exc:
            # override icontrol errors
            return (payload, exc.response)
        return (payload, req)

    def dry_run(self, payload):
        payload = self._set_action(payload, "dry-run")
        tenants = set(payload['declaration'].keys())
        tenants = list(tenants - set(['schemaVersion','class','id','remark','controls','label']))
        try:
            req = self._post("/shared/appsvcs/declare",data=json.dumps(payload))
        except HTTPError as exc:
            # override icontrol errors
            return (payload, exc.response)
        return (payload, req)
    def list_partitions(self):
        req = self._get("/tm/auth/partition")
        partitions = set([a['name'] for a in req.json()['items']]) - set(['Common'])
        return partitions

    def list_tenants(self):
        req = self.get()
        payload = req.json()
        tenants = set(payload.keys())
        tenants = list(tenants - set(['schemaVersion','class','id','remark','controls','label']))
        return tenants



    def common_objects(self, payload, common_virtual_address = None, common_node = None, disable_arp = False, traffic_group_none = None, disable_icmp = False):

        if common_virtual_address or common_node:
            virtualAddresses = []
            serverAddresses = []
            nodes = []
            tenants = set(payload['declaration'].keys())
            tenants = list(tenants - set(['schemaVersion','class','id','remark','controls','label']))
            for tenant in tenants:
                apps = set( payload['declaration'][tenant].keys())
                apps = list(apps-set(['verifiers','class']))
                for app in apps:
                    #if 'serviceMain' in payload['declaration'][tenant][app]:
                    for key in payload['declaration'][tenant][app]:
                        val = payload['declaration'][tenant][app][key]
                        if 'class' not in val:
                            continue
                        if val['class'].startswith("Service_"):
                            virtualAddresses.extend(payload['declaration'][tenant][app][key]['virtualAddresses'])
                        elif val['class'] == 'Pool':
                            for member in val['members']:
                                if 'serverAddresses' in member:
                                    serverAddresses.extend(member['serverAddresses'])


            req = self._get("/tm/ltm/node?$select=address")

            serverAddresses_existing = [a['address'] for a in req.json()['items']]
            serverAddresses_new =  set(serverAddresses) - set(serverAddresses_existing)

            nodes =  [{'name':s,'address':s,'partition':'Common'} for s in serverAddresses_new]

            req = self._get("/tm/ltm/virtual-address?$select=address")

            virtualAddresses_existing = [a['address'] for a in req.json()['items']]
            virtualAddresses_new =  set(virtualAddresses) - set(virtualAddresses_existing)
            virtuals = [{'name':s,'address':s,'partition':'Common'} for s in virtualAddresses_new]
            if disable_arp:
                for virtual in virtuals:
                    virtual['arp'] = 'disabled'
            if disable_icmp:
                for virtual in virtuals:
                    virtual['icmpEcho'] = 'disabled'
            if traffic_group_none:
                for virtual in virtuals:
                    virtual['trafficGroup'] = 'none'

            req = self._post( "/tm/transaction",data='{}')
            transId =  str(req.json()['transId'])
            print("transId")
            if nodes and args.common_node:
                for node in nodes:
                    print(node)
                    req = self._post("/tm/ltm/node",data=json.dumps(node),headers={'X-F5-REST-Coordination-Id':transId})
                req = self.icr.patch(self.base_url + "/tm/transaction/" + transId,data= '{ "state":"VALIDATING" }')

            if virtuals and args.common_virtual_address:
                req = self._post("/tm/transaction",data='{}')
                transId =  str(req.json()['transId'])
                for virtual in virtuals:
                    req = self._post("/tm/ltm/virtual-address",data=json.dumps(virtual),headers={'X-F5-REST-Coordination-Id':transId})
                req = self.icr.patch(self.base_url + "/tm/transaction/" + transId,data= '{ "state":"VALIDATING" }')

            if (nodes or virtuals) and self.persist:
                req = self._post("/tm/sys/config",data= '{"command":"save","options":[{"partitions":"{ Common }"}]}')
                print(req.json())

    def _set_action(self, payload, action):
        if "declaration" in payload:
            # set action (override any existing value)
            if "action" in payload and payload["action"] != action:
                payload["action"] = action
                #print "overriding ", action
        else:
            # add action
            payload = {"action":action,"class": "AS3", "persist": self.persist, "declaration":payload}
        if self.sync_group:
            payload["syncToGroup"] = self.sync_group
        if self.log_level != "info":
            payload["logLevel"] = self.log_level
        if self.trace or "trace" in payload:
            payload["trace"] = self.trace
        if "persist" in payload or not self.persist:
            payload["persist"] = self.persist
        return payload

    def set_payload(self, payload, action):
        return self._set_action(payload, action)

    def print_json(self, request, compact):
        if compact:
            print(req.text)
        else:
            print(json.dumps(request.json(),indent=2, sort_keys=True))
    def delete_token(self):
        req =  self.icr.delete(self.base_url + "/shared/authz/tokens/" + self.icr.token)
        return req

if __name__ == "__main__":

    parser = argparse.ArgumentParser(description='Script to manage an AS3 declaration')
    parser.add_argument("--host",             help="The IP/Hostname of the BIG-IP device",default='https://192.168.1.245/mgmt')
    parser.add_argument("-u", "--username",default='admin')
    parser.add_argument("-p", "--password",default='admin')
    parser.add_argument("--password-file",   help="The BIG-IP password stored in a file", dest='password_file')
    parser.add_argument("-a","--action",help="deploy,dry-run,delete,stub,redeploy,list(partitions),list-tenants,list-ages")
    parser.add_argument("-c","--compact",action="store_true", default=False,help="Display raw JSON output")

    parser.add_argument("-t","--tenant",help="tenant")
    parser.add_argument("--syncToGroup",dest="sync_group",help="Name of sync group to push change (default None)")
    parser.add_argument("--redeployAge",help="used with redeploy",default=0,type=int)

    parser.add_argument("--token",help="use token (remote auth)",action="store_true",default=False)
    parser.add_argument("--nopersist",dest="persist",help="do not persist",action="store_false",default=True)
    parser.add_argument("--common-virtual-address",dest="common_virtual_address",help="create virtual-address in /Common",action="store_true",default=False)
    parser.add_argument("--disable-arp",dest="disable_arp",help="disable arp when used with common-virtual-address",action="store_true",default=False)
    parser.add_argument("--disable-icmp",dest="disable_icmp",help="disable icmp when used with common-virtual-address",action="store_true",default=False)
    parser.add_argument("--traffic-group-none",dest="traffic_group_none",help="set traffic-group to none when used with common-virtual-address",action="store_true",default=False)
    parser.add_argument("--common-node",dest="common_node",help="create node in /Common",action="store_true",default=False)

    # Service Discovery Pool Options
    parser.add_argument("--sd_provider",dest="sd_provider",help="service discovery provider. ex. aws,gce")
    parser.add_argument("--sd-tag-key",dest="sd_tag_key",help="tag key used to create pool")
    parser.add_argument("--sd-tag-value",dest="sd_tag_value",help="tag value used to create pool")
    parser.add_argument("--sd-region",dest="sd_region",help="service discovery region")
    parser.add_argument("--sd-address-realm",dest="sd_address_realm",help="address type. ex. public/private", default="private")
    parser.add_argument("--sd-service-port",dest="sd_service_port",help="pool members port",action="store_true",default=80)
    parser.add_argument("--sd-update-interval",dest="sd_update_interval",help="tag polling interval",default=15)
    # Azure Specific because no ROLES
    parser.add_argument("--sd-resource-group",dest="sd_resource_group",help="resource group" )
    parser.add_argument("--sd-subscription-id",dest="sd_subscription_id",help="tag polling interval",default=15)
    parser.add_argument("--sd-directory-id",dest="sd_directory_id",help="tag polling interval",default=15)
    parser.add_argument("--sd-application-id",dest="sd_application_id",help="tag polling interval",default=15)
    parser.add_argument("--sd-api-access-key",dest="sd_api_access_key",help="tag polling interval",default=15)

    parser.add_argument("-f","--file",help="declaration JSON file")
    parser.add_argument("--level",help="log level (default info)",default="info")
    parser.add_argument("--trace",help="trace",default=False,action="store_true")
    parser.add_argument("--show",help="show")
    args = parser.parse_args()

    username = args.username
    password = args.password

    if 'F5_USERNAME' in os.environ:
        username = os.environ['F5_USERNAME']

    if 'F5_PASSWORD' in os.environ:
        password = os.environ['F5_PASSWORD']

    if args.level == 'debug':
        logging.basicConfig(level=logging.DEBUG)

    if args.password_file:
        password = open(args.password_file).readline().strip()

    if 'F5_HOST' in os.environ:
        host = os.environ['F5_HOST']
    else:
        host = args.host

    kwargs = {'host':host,
              'username':username,
              'password':password,
              'token':args.token,
              'sync_group':args.sync_group,
              'log_level':args.level,
              'trace':args.trace,
              'persist':args.persist}
    client = AS3(**kwargs)



    if args.action == 'deploy':
        if args.file == "-":
            payload_text = sys.stdin.read()
        else:
            payload_text = open(args.file).read()

        payload = json.loads(payload_text)

        # Better to use jinja but quick dirty mod to insert service discovery values in template
        pool = payload["tenant"]["https"]["pool"]["members"][0]

        payload_map = {
            'sd_tag_key': 'tagKey',
            'sd_tag_value':  'tagValue',
            'sd_provider': 'addressDiscovery',
            'sd_service_port': 'servicePort',
            'sd_update_interval': 'updateInterval',
            'sd_address_realm': 'ddressRealm',
            'sd_region': 'region',
            'sd_resource_group': 'resourceGroup',
            'sd_subscription_id': 'subscriptionId',
            'sd_directory_id': 'directoryId',
            'sd_application_id': 'applicationId',
            'sd_api_access_key': 'apiAccessKey'
        }

        # Modify payload from args
        for k,v in payload_map.iteritems():
            if args.__dict__[k]:
                pool[v] = args.__dict__[k]
        # if args.sd_tag_key:
        #     pool["tagKey"] = args.sd_tag_key
        # if args.sd_tag_value:
        #     pool["tagValue"] = args.sd_tag_value
        # if args.sd_provider:
        #     pool['addressDiscovery'] = args.sd_provider
        # if args.sd_service_port:      
        #     pool['servicePort'] = args.sd_service_port
        # if args.sd_update_interval: 
        #     pool['updateInterval'] = args.sd_update_interval
        # if args.sd_address_realm: 
        #     pool['addressRealm'] = args.sd_address_realm
        # if args.sd_region: 
        #     pool['region'] = args.sd_region
        # if args.sd_resource_group: 
        #     pool['resourceGroup'] = args.sd_resource_group
        # if args.sd_resource_group: 
        #     pool['subscriptionId'] = args.sd_subscription_id
        # if args.sd_directory_id: 
        #     pool['directoryId'] = args.sd_directory_id       
        # if args.sd_application_id: 
        #     pool['applicationId'] = args.sd_application_id
        # if args.sd_api_access_key: 
        #     pool['apiAccessKey'] = args.sd_api_access_key

        payload = client.set_payload(payload, "deploy")

        if args.tenant and 'declaration' in payload:
            # override tenant
            tenants = set(payload['declaration'].keys())
            tenants = list(tenants - set(['schemaVersion','class','id','remark','controls','label']))
            if len(tenants) > 1:
                sys.stderr.write('warning, more than 1 tenants, %d tenants found\n' %(len(tenants)))
                #print tenants
            input = raw_input("override tenant? [Y/n]: ")
            if input == "" or input.lower().startswith('y'):
                x = 0
                for tenant in tenants:
                    orig_tenant = payload['declaration'][tenant]
                    if args.tenant in payload['declaration']:
                        existing_tenant = payload['declaration'][args.tenant]
                        del payload['declaration'][tenant]
                        for app in orig_tenant:
                            if app == 'class':
                                continue
                            orig_app = orig_tenant[app]
                            if app in existing_tenant:
                                app += str(x)
                                x+=1
                                if app in existing_tenant:
                                    sys.stderr.write('warning, could not make unique app\n')
                                    input = raw_input("Continue? [N/y]: ")
                                    if input == "" or input.lower().startswith('n'):
                                        sys.exit(1)
                                existing_tenant[app] = orig_app
                        payload[args.tenant] = existing_tenant
                    else:
                        del payload['declaration'][tenant]
                        payload['declaration'][args.tenant] = orig_tenant

        client.common_objects(payload, args.common_node, args.common_virtual_address, args.disable_arp, args.traffic_group_none, args.disable_icmp)

        print(json.dumps(payload))
        req = client.post(payload)

        client.print_json(req, args.compact)
    elif args.action == 'redeploy':

        payload_text = MIN_PAYLOAD
        payload = json.loads(payload_text)
        payload = client.set_payload(payload, "redeploy")
        payload['redeployAge'] = args.redeployAge
        del payload['declaration']
        print(json.dumps(payload))
        req = client.post(payload)

        client.print_json(req, args.compact)

    elif args.action == 'patch':
        logging.debug("patching...")
        if args.file == "-":
            payload_text = sys.stdin.read()
        else:
            payload_text = open(args.file).read()
        
        payload = json.loads(payload_text)

        print(json.dumps(payload))

        req = client.icr.patch(client.base_url + "/shared/appsvcs/declare/",data=payload_text)

        client.print_json(req, args.compact)

    elif args.action == 'stub' and args.tenant:

        payload_text = MIN_PAYLOAD %(args.tenant)

        payload = json.loads(payload_text)
        print(json.dumps(payload))

        payload = client.set_payload(payload, "deploy")

        req = client.post(payload)

        client.print_json(req, args.compact)

        if req.status_code != 200:
            sys.exit(1)

    elif args.action == 'deploy-by-tenant':
        payload_text = open(args.file).read()
        payload = json.loads(payload_text)
        if 'declaration' in payload:
            tenants = set(payload['declaration'].keys())
            tenants = list(tenants - set(['schemaVersion','class','id']))

            tenants.sort()
            print(tenants)
            base = {'schemaVersion':payload['declaration']['schemaVersion'],
                    'class':payload['declaration']['class'],
                    'id':payload['declaration']['id']}
            for tenant in tenants:
                declaration = base.copy()
                declaration[tenant] = payload['declaration'][tenant]
                new_payload = client.set_payload(declaration, "deploy")
                print(json.dumps(new_payload))
                req = client.post(new_payload)
                client.print_json(req, args.compact)

    #    payload = set_action(payload, "deploy", args.sync_group,args.level,args.trace,args.persist)
    #    print json.dumps(payload)
    #    req = icr.post(base_url + "/shared/appsvcs/declare",data=json.dumps(payload))

    #    print_json(req, args.compact)


    elif args.action == 'delete-by-tenant':
        payload_text = open(args.file).read()
        payload = json.loads(payload_text)
        if 'declaration' in payload:
            tenants = set(payload['declaration'].keys())
            tenants = list(tenants - set(['schemaVersion','class','id']))

            tenants.sort()
            print(tenants)
            base = {'schemaVersion':payload['declaration']['schemaVersion'],
                    'class':payload['declaration']['class'],
                    'id':payload['declaration']['id']}
            for tenant in tenants:
                declaration = json.loads("""
                {
                "class": "ADC",
                "schemaVersion": "3.0.0",
                "id":"deleteme",
                "%s": {
                "class": "Tenant"
                }
                }
                """ %(tenant))
                new_payload = client.set_payload(declaration, "deploy")
                print(json.dumps(new_payload))
                req = client.post(new_payload)
                client.print_json(req, args.compact)

    #    payload = set_action(payload, "deploy", args.sync_group,args.level,args.trace,args.persist)
    #    print json.dumps(payload)
    #    req = icr.post(base_url + "/shared/appsvcs/declare",data=json.dumps(payload))

    #    print_json(req, args.compact)




    elif args.action == 'dry-run':

        if args.file == "-":
            payload_text = sys.stdin.read()
        else:
            payload_text = open(args.file).read()

        payload = json.loads(payload_text)

        payload = client.set_payload(payload, "dry-run")
        print(json.dumps(payload))
        req = client.post(payload)

        client.print_json(req, args.compact)

        if req.status_code != 200:
            sys.exit(1)

    elif args.action == 'delete' and args.tenant:
        payload = json.loads("""
    {
      "class": "ADC",
      "schemaVersion": "3.0.0",
      "id":"deleteme",
      "%s": {
        "class": "Tenant"
      }
        }
        """ %(args.tenant))
#        payload = json.loads("""{}""")

        payload = client.set_payload(payload, "deploy")
#        payload = client.set_payload(payload, "remove")

        print(json.dumps(payload))
#        print(payload)
        req = client.post(payload)
#        req = client._post("/shared/appsvcs/declare",data=payload)

        client.print_json(req, args.compact)
    elif args.action == 'deleteall':
        payload = json.loads("""
    {
      "class": "ADC",
      "schemaVersion": "3.0.0",
      "id":"deletemeeverything"
    }
        """)
        #print(json.dumps(payload))
        #payload['declaration'] = {}
        #payload={'class':'AS3','action':'deploy','declaration':payload}
        #payload={'class':'AS3','action':'deploy','declaration':{}}
        #req = client.deploy(payload)
        req = client.icr.delete(client.base_url + "/shared/appsvcs/declare/")

        client.print_json(req, args.compact)

    elif args.tenant:
        uri = args.tenant
        if args.show:
            uri += "?show=%s" %(args.show)
        print(uri)
        req = client.get(uri)
        client.print_json(req, args.compact)
    elif args.action == 'version':
        req = client._get("/shared/appsvcs/info")

        client.print_json(req, args.compact)

    elif args.action == 'selftest':
        payload = json.loads("""
    {
    }
        """)

        print(json.dumps(payload))

        req = client._post("/shared/appsvcs/selftest",data=json.dumps(payload))

        client.print_json(req, args.compact)
    elif args.action == 'list-partitions' or args.action == 'list':
        partitions = client.list_partitions()
        print("\n".join(partitions))
    elif args.action == 'list-tenants' or args.action == 'tenants':
        tenants = client.list_tenants()
        print("\n".join(tenants))
    elif args.action == 'list-ages':
        req = client._get("/shared/appsvcs/declare?age=list")
        client.print_json(req, args.compact)
    else:
        req= client.get()
        client.print_json(req, args.compact)

    # delete token
    if args.token:
        req = client.delete_token()
