import csv
import json
import pprint
import subprocess
import sys

''' 
This script is intended to parse a DIAMETER PCAP file to JSON, it is designed to work on both CCR and CCA messages
This means there will be two output files, one which contains all of the CCR transactions and one which contains all of the CCA transactions,
We can use | transaction later if we wish to link the two events together
'''

# You must call this function with the type of DIAMETER message to parse and the pcap file to perform it on
# Your options are CCR or CCA 
def tshark(type,pcapfile):
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
	"diameter_3gpp_imsi_mcc_mnc",
	# "diameter_3gpp_nsapi",
	# "diameter_3gpp_pdp_type",
	# "diameter_3gpp_rat_type",
	# "diameter_3gpp_sgsn_mcc_mnc",
	# "diameter_3gpp_selection_mode",
	# "diameter_3gpp_session_stop_indicator",
	# "diameter_3gpp_user_location_info",
	# "diameter_auth_application_id",
	# "diameter_cc_input_octets",
	# "diameter_cc_output_octets",
	# "diameter_cc_request_number",
	# "diameter_cc_request_type",
	# "diameter_cc_service_specific_units",
	# "diameter_cc_time",
	# "diameter_cc_total_octets",
	# "diameter_cg_address",
	# "diameter_cg_address_ipv4",
	# "diameter_cg_address_addr_family",
	# "diameter_called_station_id",
	# "diameter_charging_rule_base_name",
	# "diameter_destination_host",
	# "diameter_destination_realm",
	# "diameter_event_timestamp",
	# "diameter_ggsn_address",
	# "diameter_ggsn_address_ipv4",
	# "diameter_ggsn_address_addr_family",
	# "diameter_multiple_services_credit_control",
	# "diameter_multiple_services_indicator",
	# "diameter_origin_host",
	# "diameter_origin_realm",
	# "diameter_origin_state_id",
	# "diameter_pdp_address",
	# "diameter_pdp_address_ipv4",
	# "diameter_pdp_address_addr_family",
	# "diameter_pdp_context_type",
	# "diameter_ps_information",
	# "diameter_rating_group",
	# "diameter_reporting_reason",
	# "diameter_requested_service_unit",
	# "diameter_sgsn_address",
	# "diameter_sgsn_address_ipv4",
	# "diameter_sgsn_address_addr_family",
	# "diameter_service_context_id",
	# "diameter_service_identifier",
	# "diameter_service_information",
	# "diameter_session_id",
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
	# "diameter_user_name",
	# "diameter_applicationid",
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

	cca_selected_fields = [  
	"src_ip",
	"dest_ip",
	"diameter_auth_application_id",
	"diameter_cc_input_octets",
	# "diameter_cc_output_octets",
	# "diameter_cc_request_number",
	# "diameter_cc_request_type",
	# "diameter_cc_total_octets",
	# "diameter_final_unit_action",
	# "diameter_final_unit_indication",
	# "diameter_granted_service_unit",
	# "diameter_multiple_services_credit_control",
	"diameter_origin_host",
	"diameter_origin_realm",
	# "diameter_rating_group",
	# "diameter_redirect_address_type",
	# "diameter_redirect_server",
	# "diameter_redirect_server_address",
	"diameter_result_code",
	"diameter_service_identifier",
	"diameter_session_id",
	# "diameter_trigger",
	"diameter_trigger_type",
	# "diameter_validity_time",
	# "diameter_answer_to",
	# "diameter_applicationid",
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
	"diameter_resp_time",
	# "diameter_version",
]

	''' 
	Build up required tshark fields as well as the JSON fields
	'''
	tshark_fields = ''
	json_output_fields = ''
	fieldnames = ['time']

	if type == 'CCR':	
		for i in ccr_selected_fields:
			tshark_fields += "-e " + diameter_dictionary[i] + " "
			fieldnames.extend([i])
	elif type == 'CCA':
		for i in cca_selected_fields:
			tshark_fields += "-e " + diameter_dictionary[i] + " "
			fieldnames.extend([i])
	else:
		print "You need to specificy CCR or CCA"

	''' Excute tshark against a PCAP file and store the results to a csv file'''
	tshark_filename = pcapfile
	if type == 'CCA':	
		tshark_filter = '(diameter.flags.request == 0) && (diameter.applicationId == 4)'
		csv_filename = 'cca.csv'
		json_filename = 'cca.json'
	elif type == 'CCR':
		tshark_filter = '(diameter.flags.request == 1) && (diameter.applicationId == 4)'
		csv_filename = 'ccr.csv'
		json_filename = 'ccr.json'
	else:
		print "You need to specificy CCR or CCA"

	# tshark_filter = 'diameter'
	tshark_aggregator = '/s'
	tshark_delim = ','
	tshark_full_command = 'tshark -r %s -Y "%s" -E separator=%s -E aggregator=%s -T fields -e frame.time_epoch %s' % (tshark_filename, tshark_filter, tshark_delim, tshark_aggregator, tshark_fields)
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
	    json.dump(row, jsonfile, indent=4,sort_keys=True)
	    jsonfile.write('\n')
	    # print row

	jsonfile.close()
	csvfile.close()

tshark('CCR',sys.argv[1])
tshark('CCA',sys.argv[1])