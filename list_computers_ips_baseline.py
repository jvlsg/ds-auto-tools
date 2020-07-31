import sys, warnings
import deepsecurity
from deepsecurity.rest import ApiException
import argparse

URL = 'app.deepsecurity.trendmicro.com/api'
API_KEY = ''
API_VERSION = 'v1'
BASELINE_ID = None
BASELINE_HOSTNAME = None
API_CLIENT = None

def setup(parsed_args):
    global URL
    global API_KEY
    global BASELINE_ID
    global BASELINE_HOSTNAME
    global API_CLIENT

    #BASLINE
    if parsed_args.url:
        URL = parsed_args.url
    if parsed_args.key:
        API_KEY = parsed_args.key
    if parsed_args.id:
        BASELINE_ID = int(parsed_args.id)
    if parsed_args.hostname:
        BASELINE_HOSTNAME = parsed_args.hostname
    
    if (BASELINE_ID == None) and (BASELINE_HOSTNAME == None):
        print("No baseline computer selected. Pass ID or Hostname")
        sys.exit(-1)
    
    if not sys.warnoptions:
        warnings.simplefilter("ignore")
    
    configuration = deepsecurity.Configuration()
    configuration.host = URL
    configuration.api_key['api-secret-key'] = API_KEY
    API_CLIENT = deepsecurity.ApiClient(configuration)

def fetch_computers():
    api_instance = deepsecurity.ComputersApi(API_CLIENT)
    overrides = False
    try:
        print("Connecting...")
        api_response = api_instance.list_computers(API_VERSION, overrides=overrides)
    except ApiException as e:
        print("An exception occurred when calling ComputersApi.list_computers: %s\n" % e)
    else:
        print("Computer fetch successful")
        return api_response.computers

def find_in_baseline(computer_list):
    print("Processing...")

    identifier_lambda = None
    if BASELINE_ID:
        identifier_lambda = lambda c: c.id==BASELINE_ID
    elif BASELINE_HOSTNAME:
        identifier_lambda = lambda c: c.host_name==BASELINE_HOSTNAME
    
    baseline_computer = None
    try:
        baseline_computer = list(filter(identifier_lambda,computer_list))[0]
    except IndexError:
        print("No Computer with that ID/Hostname")
        exit(1)
    

    baseline_rules_set = set(baseline_computer.intrusion_prevention.rule_ids)
    computer_list.remove(baseline_computer)

    computer_in_baseline_list = []
    computer_not_in_baseline_list = []
    
    for c in computer_list:
        if c.intrusion_prevention.rule_ids == None:
            continue
        c_rules_set = set(c.intrusion_prevention.rule_ids)
        diff = baseline_rules_set.union(c_rules_set) - baseline_rules_set.intersection(c_rules_set)
        if diff == 0:
            computer_in_baseline_list.append(c)
        else:
            computer_not_in_baseline_list.append( (c,len(diff)) )

    computer_not_in_baseline_list.sort(key=lambda t: t[1])
    for c in computer_in_baseline_list:
        print("{} | IN BASELINE | Computer Group ID:{}".format(c.host_name,c.group_id))
    for t in computer_not_in_baseline_list:
        print("{} | {} rules difference | Computer Group ID:{}".format(t[0].host_name,t[1],t[0].group_id))

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--id','-i', help="ID of the computer to be used for the baseline. Overrides Hostname option")
    parser.add_argument('--hostname','-n', help="Hostname of the computer to be used for the baseline. If more than one computers w/ hostname, will select the first")
    parser.add_argument('--url','-u', help="API URL (add /api in the end)")
    parser.add_argument('--key','-k', help="API Key w/ Computer VIEW permission")
    parsed_args = parser.parse_args()
    
    setup(parsed_args)
    computer_list = fetch_computers()
    find_in_baseline(computer_list)
    exit(0)