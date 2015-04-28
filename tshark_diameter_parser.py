import csv
import json
import pprint
import subprocess
import sys
import datetime
import calendar

'''
This script is intended to parse a DIAMETER PCAP file to JSON, it is designed to work on both CCR and CCA messages
This means there will be two output files, one which contains all of the CCR transactions and one which contains all of the CCA transactions,
We can use | transaction later if we wish to link the two events together
'''

# You must call this function with the type of DIAMETER message to parse and the pcap file to perform it on
# Your options are CCR or CCA
def tshark_ccr(pcapfile,jsonoutputlocation):
        ''' Loading in lowercase fiels names along with the tshark ones so we can build a dictionary for use later'''
        diameter_fields = csv.reader(open('tshark_diameter_fields.csv', 'r'))
        diameter_dictionary = {}

        for row in diameter_fields:
                key = row[0]
                diameter_dictionary[key] = row[1]

        '''Comment out the fields below that you DONT want included in the final output'''

        ccr_selected_fields = [
        "src_ip",
        "dest_ip",
        "diameter_3gpp_charging_characteristics",
        "diameter_3gpp_charging_id",
        "diameter_3gpp_ggsn_mcc_mnc",
        "diameter_3gpp_gprs_negotiated_qos_profile",
        # "diameter_3gpp_imsi_mcc_mnc",
        # "diameter_3gpp_nsapi",
        "diameter_3gpp_pdp_type",
        "diameter_3gpp_rat_type",
        "diameter_3gpp_sgsn_mcc_mnc",
        # "diameter_3gpp_selection_mode",
        # "diameter_3gpp_session_stop_indicator",
        # "diameter_3gpp_user_location_info",
        "diameter_auth_application_id",
        # "diameter_cc_input_octets",
        # "diameter_cc_output_octets",
        "diameter_cc_request_number",
        "diameter_cc_request_type",
        # "diameter_cc_service_specific_units",
        # "diameter_cc_time",
        # "diameter_cc_total_octets",
        # "diameter_cg_address",
        # "diameter_cg_address_ipv4",
        # "diameter_cg_address_addr_family",
        "diameter_called_station_id",
        "diameter_charging_rule_base_name",
        # "diameter_destination_host",
        # "diameter_destination_realm",
        # "diameter_event_timestamp",
        # "diameter_ggsn_address",
        # "diameter_ggsn_address_ipv4",
        # "diameter_ggsn_address_addr_family",
        # "diameter_multiple_services_credit_control",
        # "diameter_multiple_services_indicator",
        "diameter_origin_host",
        "diameter_origin_realm",
        # "diameter_origin_state_id",
        # "diameter_pdp_address",
        "diameter_pdp_address_ipv4",
        # "diameter_pdp_address_addr_family",
        # "diameter_pdp_context_type",
        # "diameter_ps_information",
        "diameter_rating_group",
        "diameter_reporting_reason",
        # "diameter_requested_service_unit",
        # "diameter_sgsn_address",
        "diameter_sgsn_address_ipv4",
        # "diameter_sgsn_address_addr_family",
        # "diameter_service_context_id",
        "diameter_service_identifier",
        # "diameter_service_information",
        "diameter_session_id",
        # "diameter_subscription_id",
        # "diameter_subscription_id_data",
        # "diameter_subscription_id_type",
        # "diameter_termination_cause",
        # "diameter_trigger",
        # "diameter_trigger_type",
        # "diameter_used_service_unit",
        # "diameter_user_equipment_info",
        # "diameter_user_equipment_info_type",
        # "diameter_user_equipment_info_value",
        "diameter_user_name",
        "diameter_applicationid",
        # "diameter_avp",
        # "diameter_avp_code",
        # "diameter_avp_flags",
        # "diameter_avp_flags_protected",
        # "diameter_avp_flags_reserved3",
        # "diameter_avp_flags_reserved4",
        # "diameter_avp_flags_reserved5",
        # "diameter_avp_flags_reserved6",
        # "diameter_avp_flags_reserved7",
        # "diameter_avp_len",
        # "diameter_avp_pad",
        # "diameter_avp_vendorid",
        "diameter_cmd_code",
        "diameter_endtoendid",
        # "diameter_flags",
        # "diameter_flags_t",
        # "diameter_flags_error",
        # "diameter_flags_mandatory",
        # "diameter_flags_proxyable",
        # "diameter_flags_request",
        # "diameter_flags_reserved4",
        # "diameter_flags_reserved5",
        # "diameter_flags_reserved6",
        # "diameter_flags_reserved7",
        # "diameter_flags_vendorspecific",
        # "diameter_hopbyhopid",
        # "diameter_length",
        # "diameter_version"
        ]

        '''
        Build up required tshark fields as well as the JSON fields
        '''
        tshark_fields = ''
        json_output_fields = ''
        fieldnames = ['time']

        for i in ccr_selected_fields:
                tshark_fields += "-e " + diameter_dictionary[i] + " "
                fieldnames.extend([i])
       
        ''' Excute tshark against a PCAP file and store the results to a csv file'''
        tshark_filename = pcapfile
        now = datetime.datetime.now().strftime("%Y%-m%-d_%H%M%S")
      
        tshark_filter = '(diameter.flags.request == 1) && (diameter.applicationId == 4)'
        csv_filename = '/tmp/ccr.csv'
        json_filename = jsonoutputlocation + '/ccr_' + now + '.json'

        # tshark_filter = 'diameter'
        tshark_aggregator = '/s'
        tshark_delim = ','
        tshark_full_command = '/opt/tshark/bin/tshark -r %s -Y "%s" -E separator=%s -E aggregator=%s -T fields -e frame.time_epoch %s' % (tshark_filename, tshark_filter, tshark_delim, tshark_aggregator, tshark_fields)
        # print tshark_full_command
        p = subprocess.Popen(tshark_full_command, stdout=subprocess.PIPE, shell=True)
        (output, err) = p.communicate()
        tshark_raw_out = open(csv_filename, 'w')
        tshark_raw_out.write(output)
        tshark_raw_out.close()

        ''' Read the previously outputted CSV file and convert it to JSON'''

        csvfile = open(csv_filename, 'r')
        jsonfile = open(json_filename, 'w')
        reader = csv.DictReader(csvfile, fieldnames)

        for row in reader:
                row['time'] = datetime.datetime.fromtimestamp(float(row['time'])).isoformat()
                json.dump(row, jsonfile, indent=4,sort_keys=True)
                jsonfile.write('\n')

        jsonfile.close()
        csvfile.close()

def tshark_cca(pcapfile,jsonoutputlocation):
        ''' Loading in lowercase fiels names along with the tshark ones so we can build a dictionary for use later'''
        diameter_fields = csv.reader(open('tshark_diameter_fields.csv', 'r'))
        diameter_dictionary = {}

        for row in diameter_fields:
                key = row[0]
                diameter_dictionary[key] = row[1]

        '''Comment out the fields below that you DONT want included in the final output'''

        cca_selected_fields = [  
        # "src_ip",
        # "dest_ip",
        "diameter_auth_application_id",
        "diameter_cc_input_octets",
        "diameter_cc_output_octets",
        "diameter_cc_request_number",
        "diameter_cc_request_type",
        "diameter_cc_total_octets",
        "diameter_final_unit_action",
        # "diameter_final_unit_indication",     '''HEX GARBAGE'''
        # "diameter_granted_service_unit",      '''HEX GARBAGE'''
        # "diameter_multiple_services_credit_control",
        "diameter_origin_host",
        "diameter_origin_realm",
        "diameter_rating_group",
        # # "diameter_redirect_address_type",
        # "diameter_redirect_server",           '''HEX GARBAGE'''
        "diameter_redirect_server_address",
        "diameter_result_code",
        "diameter_service_identifier",
        "diameter_session_id",
        # # "diameter_trigger",                 '''HEX GARBAGE'''
        "diameter_trigger_type",
        "diameter_validity_time",
        # "diameter_answer_to",
        "diameter_applicationid",
        # # "diameter_avp",
        # # "diameter_avp_code",
        # # "diameter_avp_flags",
        # # "diameter_avp_flags_protected",
        # # "diameter_avp_flags_reserved3",
        # # "diameter_avp_flags_reserved4",
        # # "diameter_avp_flags_reserved5",
        # # "diameter_avp_flags_reserved6",
        # # "diameter_avp_flags_reserved7",
        # # "diameter_avp_len",
        # # "diameter_avp_pad",
        # # "diameter_avp_vendorid",
        # "diameter_cmd_code",
        "diameter_endtoendid",
        # "diameter_flags",
        # "diameter_flags_t",
        # "diameter_flags_error",
        # "diameter_flags_mandatory",
        # "diameter_flags_proxyable",
        # "diameter_flags_request",
        # "diameter_flags_reserved4",
        # "diameter_flags_reserved5",
        # "diameter_flags_reserved6",
        # "diameter_flags_reserved7",
        # "diameter_flags_vendorspecific",
        # "diameter_hopbyhopid",
        # "diameter_length",
        # "diameter_resp_time",
        # "diameter_version",
]

        ''' 
        Build up required tshark fields as well as the JSON fields
        '''
        tshark_fields = ''
        json_output_fields = ''
        fieldnames = ['time']
        tshark_filename = pcapfile
        now = datetime.datetime.now().strftime("%Y%-m%-d_%H%M%S")

        for i in cca_selected_fields:
                tshark_fields += diameter_dictionary[i] + ","
                fieldnames.extend([i])

        temp_cca_filename = '/tmp/cca.raw'
        json_filename = jsonoutputlocation + '/cca_' + now + '.json'
        tshark_fields = tshark_fields[:-1]

        tshark_filter = '(diameter.flags.request == 0) && (diameter.applicationId == 4)'
        tshark_full_command = '/opt/tshark/bin/tshark -r %s -Y "%s" -q -z diameter,avp,272,%s | grep frame' % (tshark_filename,tshark_filter,tshark_fields)
        print tshark_full_command
        p = subprocess.Popen(tshark_full_command, stdout=subprocess.PIPE, shell=True)
        (output, err) = p.communicate()
        tshark_raw_out = open(temp_cca_filename, 'w')
        output = output.replace("End-to-End Identifier", "endtoendid")
        tshark_raw_out.write(output)
        tshark_raw_out.close()

        cca_rawfile = open(temp_cca_filename, 'r')
        jsonfile = open(json_filename, 'w')


        ''' Update this list to omit non-required fieds '''
        ignored_fields = ["Request", "msgnr", "srcport", "req_frame", "proto", "is_request", "dstport", "ans_frame"]

        cca_dict = {}

        clean_dict = {
        'ApplicationId':'diameter_applicationid',
        'Auth_Application_Id':'diameter_auth_application_id',
        'CC_Input_Octets':'diameter_cc_input_octets',
        'CC_Output_Octets':'diameter_cc_output_octets',
        'CC_Request_Number':'diameter_cc_request_number',
        'CC_Request_Type':'diameter_cc_request_type',
        'CC_Total_Octets':'diameter_cc_total_octets',
        'Final_Unit_Action':'diameter_final_unit_action',
        'Origin_Host':'diameter_origin_host',
        'Origin_Realm':'diameter_origin_realm',
        'Redirect_Server_Address':'diameter_redirect_server_address',
        'Rating_Group':'diameter_rating_group',
        'Service_Identifier':'diameter_service_identifier',
        'Session_Id':'diameter_session_id',
        'Trigger_Type':'diameter_trigger_type',
        'Validity_Time':'diameter_validity_time',
        'cmd':'diameter_cmd_code',
        'endtoendid':'diameter_endtoendid',
        'src':'src_ip',
        'dst':'dest_ip'
}

        with open(temp_cca_filename) as f:
            for line in f:
                if "is_request='0'" in line:
                    result_code_count=line.count("Result-Code=")
                    if result_code_count == 1:
                        print "Single Result Code"
                        print line
                        line = line.replace("Result-Code", "diameter_result_code", 1)
                        g = line.strip().split(' ')
                        for h in g:
                            i = h.strip().split('=')
                            i[0] = i[0].replace("-", "_")
                            i[1] = i[1].replace("'", "")

                            if i[0] not in ignored_fields:
                                    if i[0] in clean_dict.keys():
                                            cca_dict[clean_dict[i[0]]]= i[1]
                                    elif i[0] == "time":
                                             cca_dict[i[0]] = datetime.datetime.fromtimestamp(float(i[1])).isoformat()
                                    else:
                                             cca_dict[i[0]] = i[1]

                    # elif result_code_count == 2:
                    #     print "Two Result Codes"
                    #     print line
                    # # print line
                    #     line = line.replace("Result-Code", "diameter_result_code", 1)
                    #     line = line.replace("Result-Code", "diameter_mscc_result_code", 1)
                    #     g = line.strip().split(' ')
                    #     for h in g:
                    #         i = h.strip().split('=')
                    #         i[0] = i[0].replace("-", "_")
                    #         i[1] = i[1].replace("'", "")

                    #         if i[0] not in ignored_fields:
                    #                 if i[0] in clean_dict.keys():
                    #                         cca_dict[clean_dict[i[0]]]= i[1]
                    #                 elif i[0] == "time":
                    #                          cca_dict[i[0]] = datetime.datetime.fromtimestamp(float(i[1])).isoformat()
                    #                 else:
                    #                         cca_dict[i[0]] = i[1]

                json.dump(cca_dict, jsonfile, indent=4,sort_keys=True)
                jsonfile.write('\n')

def menu():
        if len(sys.argv) < 3:
                print '''
tshark_diameter parser, you must pass in the following options to process the pcap files

python tshark_diameter_parser.py <PCAPFILENAME> <OUTPUTPATH>'''
        elif len(sys.argv) == 3:
                # tshark_ccr(sys.argv[1],sys.argv[2])
                tshark_cca(sys.argv[1],sys.argv[2])

menu()


#                 print '''
# tshark_diameter parser, you must pass in the following options to process the pcap files

# python tshark_diameter_parser.py <PCAPFILENAME> <OUTPUTPATH>
# '''
