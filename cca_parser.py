import csv
import json
import pprint
import subprocess
import sys
import datetime
import re

''' 
This script is intended to parse a DIAMETER PCAP file to JSON, it is designed to work on both CCR and CCA messages
This means there will be two output files, one which contains all of the CCR transactions and one which contains all of the CCA transactions,
We can use | transaction later if we wish to link the two events together
'''

def tshark_cca(pcapfile):
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
	# "diameter_final_unit_indication",
	# "diameter_granted_service_unit",
	# "diameter_multiple_services_credit_control",
	"diameter_origin_host",
	"diameter_origin_realm",
	"diameter_rating_group",
	# # "diameter_redirect_address_type",
	# # "diameter_redirect_server",
	# # "diameter_redirect_server_address",
	"diameter_result_code",
	# "diameter_service_identifier",
	"diameter_session_id",
	# # "diameter_trigger",
	"diameter_trigger_type",
	# # "diameter_validity_time",
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

	for i in cca_selected_fields:
		tshark_fields += diameter_dictionary[i] + ","
		fieldnames.extend([i])

	csv_filename = 'cca.csv'
	temp_cca_filename = 'cca.raw'
	json_filename = 'cca.json'
	tshark_fields = tshark_fields[:-1]
	delete_char = "'"

	tshark_filter = '(diameter.flags.request == 0) && (diameter.applicationId == 4)'
	tshark_full_command = 'tshark -r %s -Y "%s" -q -z diameter,avp,272,%s | grep frame' % (tshark_filename,tshark_filter,tshark_fields)
	# print tshark_full_command
	p = subprocess.Popen(tshark_full_command, stdout=subprocess.PIPE, shell=True)
	(output, err) = p.communicate()
	tshark_raw_out = open(temp_cca_filename, 'w')
	output = output.replace("End-to-End Identifier", "endtoendid")
	tshark_raw_out.write(output)
	tshark_raw_out.close()

	cca_rawfile = open(temp_cca_filename, 'r')
	jsonfile = open(json_filename, 'w')


	''' Update this list to omit non-required fieds '''
	ignored_fields = ["frame", "request", "msgnr", "srcport", "req_frame", "proto", "is_request", "dstport", "ans_frame"]

	cca_dict = {}
	with open(temp_cca_filename) as f:
	    for line in f:
	    		line = line.replace("Result-Code", "base_result_code", 1)
	    		line = line.replace("Result-Code", "nested_result_code", 1)
		    	g = line.strip().split(' ')
		    	for h in g:
		    		i = h.strip().split('=')
		    		i[0] = i[0].replace("-", "_").lower()
		    		i[1] = i[1].replace("'", "")

				if i[0] not in ignored_fields:
					cca_dict[i[0]] = i[1]

			json.dump(cca_dict, jsonfile, indent=4,sort_keys=True)
			jsonfile.write('\n')

	 
tshark_cca(sys.argv[1])