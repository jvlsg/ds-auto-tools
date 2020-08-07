import sys, warnings
import deepsecurity
from deepsecurity.rest import ApiException
import argparse
import pprint
import csv

URL = 'app.deepsecurity.trendmicro.com/api'
API_KEY = ''
API_VERSION = 'v1'
API_CLIENT = None
MAX_ITEMS_PER_PAGE = 1000 #Up To 5000
EXPORT_CSV = False

def setup(parsed_args):
    global URL
    global API_KEY
    global API_CLIENT
    global EXPORT_CSV

    #BASLINE
    if parsed_args.url:
        URL = parsed_args.url
    if parsed_args.key:
        API_KEY = parsed_args.key
    if parsed_args.csv:
        EXPORT_CSV = parsed_args.csv
    
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
        api_response = api_instance.list_computers(API_VERSION, overrides=overrides)
    except ApiException as e:
        print("An exception occurred when calling ComputersApi.list_computers: %s\n" % e)
    else:
        return api_response.computers

def fetch_assignments_recommendations(computer_id):
    api_instance = deepsecurity.ComputerIntrusionPreventionRuleAssignmentsRecommendationsApi(API_CLIENT)
    overrides = False

    try:
        api_response = api_instance.list_intrusion_prevention_rule_ids_on_computer(computer_id, API_VERSION, overrides=overrides)
    except ApiException as e:
        print("An exception occurred when calling ComputerIntrusionPreventionRuleAssignmentsRecommendationsApi.list_intrusion_prevention_rule_ids_on_computer: %s\n" % e)
    else:
        return api_response

def fetch_intrusion_prevetion_rules():
    api_instance = deepsecurity.IntrusionPreventionRulesApi(API_CLIENT)
    
    search_criteria = deepsecurity.SearchCriteria()
    search_criteria.id_value = 0
    search_criteria.id_test = "greater-than"    
    
    search_filter = deepsecurity.SearchFilter(max_items=MAX_ITEMS_PER_PAGE, search_criteria=search_criteria)

    ips_rules_list=[]
    while True:
        paged_response = api_instance.search_intrusion_prevention_rules(API_VERSION, search_filter=search_filter)
        ips_rules_list+=paged_response.intrusion_prevention_rules
        last_id = ips_rules_list[-1].id
        search_filter.search_criteria.id_value = last_id

        if len(paged_response.intrusion_prevention_rules) != search_filter.max_items:
            break

    return ips_rules_list

def fetch_application_types():
    api_instance = deepsecurity.ApplicationTypesApi(API_CLIENT)

    try:
        api_response = api_instance.list_application_types(API_VERSION)
    except ApiException as e:
        print("An exception occurred when calling ApplicationTypesApi.list_application_types: %s\n" % e)
    else:
        return api_response.application_types

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--url','-u', help="API URL (add /api in the end)")
    parser.add_argument('--key','-k', help="API Key w/ Computer VIEW permission")
    parser.add_argument('--csv', help="Export CSV File with results", action='store_true')
    parsed_args = parser.parse_args()
    
    setup(parsed_args)
    print("Connecting...")
    
    print("Intrusion Prevention Rules")
    ips_rules_dict = {rule.id:rule for rule in fetch_intrusion_prevetion_rules()}
        
    print("Fetching Application Types")
    application_types_dict = {app.id:app for app in fetch_application_types()}
    
    print("Fetching Computers")
    computer_list = fetch_computers()

    assigned_recommended_ips_rules_computer_dict = {}

    if EXPORT_CSV:
        csv_file = open('application_types.csv','w')
        csv_writer = csv.writer(csv_file)
        
    for c in computer_list:
        aux=fetch_assignments_recommendations(c.id)
        if aux == None:
            continue
        
        if aux.recommendation_scan_status not in ['out-of-date','valid']:
            continue

        recommended_application_type_ids = [ips_rules_dict[r_id].application_type_id for r_id in aux.recommended_to_assign_rule_ids]
        app_types_ids_in_computer = list(set(recommended_application_type_ids) | set(aux.assigned_application_type_ids))
        app_types_names_in_computer = []
        for app_id in app_types_ids_in_computer:
            app_types_names_in_computer.append(application_types_dict[app_id].name)
        app_types_names_in_computer.sort()

        print("COMPUTER: {}".format(c.host_name))
        print("Detected Application Types:")
        pprint.pprint(app_types_names_in_computer,indent=4)
        print("\n")

        if EXPORT_CSV:
            csv_writer.writerow([c.host_name,app_types_names_in_computer])

    if EXPORT_CSV:
        csv_file.close()
    exit(0)