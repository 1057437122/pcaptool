#!/usr/bin/python
import MySQLdb as mysql
import random
import threading
import time
import datetime
import pyshark
import sys

def w2log(log_str):

	# print str

	file_obj = open('pcap_analysis.log','a+')

	try:

		log_str = log_str + str(time.strftime("%Y%m%d %X",time.localtime()))

		file_obj.write(log_str+'\n')

	except:

		print 'fail:',sys.exc_info()[0]

	finally:

		file_obj.close()

class PcapHandler:

	def __init__(self):

		self.sql = ''

		self.data = {}

		self.sql_header = 'insert into pcap_packets (tcp_hdr_len,ip_addr,tcp_checksum,tcp_options_type,http_accept_language,http_request_version,tcp_flags_urg,eth_dst,pkt_transport_layer,eth_type,tcp_option_kind,tcp_options_type_class,tcp_options_timestamp_tsecr,http_request_method,tcp_checksum_good,ip_src_host,tcp_flags_res,http_connection,pkt_sniff_timestamp,tcp_flags_push,ip_proto,tcp_options_timestamp_tsval,tcp_options,http_request,http_expert_group,ip_host,tcp_window_size,http_accept,tcp_analysis_bytes_in_flight,ip_checksum,tcp_window_size_scalefactor,ip_ttl,ip_checksum_good,eth_ig,tcp_stream,tcp_flags_syn,tcp_len,tcp_options_type_copy,ip_id,http_request_uri,ip_dsfield_ecn,pkt_length,ip_dsfield,tcp_window_size_value,ip_checksum_bad,ip_version,http_content_length,tcp_flags_cwr,eth_src,http_cache_control,ip_len,ip_src,http_expert,ip_hdr_len,http_content_length_header,ip_flags_mf,http_content_type,ip_frag_offset,ip_flags_df,http_request_full_uri,tcp_flags_ns,http_expert_severity,http_expert_message,tcp_flags,http_user_agent,tcp_ack,ip_dst,ip_flags_rb,pkt_sniff_time,tcp_option_len,tcp_flags_fin,tcp_flags_ecn,tcp_checksum_bad,tcp_flags_reset,tcp_flags_ack,pkt_captured_length,tcp_options_type_number,ip_flags,pkt_number,ip_dsfield_dscp,http_host,ip_dst_host,tcp_nxtseq,tcp_dstport,tcp_srcport,tcp_seq,eth_addr,eth_lg,tcp_analysis,tcp_port) values '

		self.pkt_struct = {
			'pkt':['captured_length','length','sniff_time','sniff_timestamp','number','transport_layer'],
			'eth':['dst', 'lg', 'addr', 'ig', 'type', 'src'],
			'ip':['flags_mf', 'ttl', 'version', 'dst_host', 'flags_df', 'flags', 'dsfield', 'src_host', 'checksum_good', 'id', 'checksum', 'dsfield_ecn', 'hdr_len', 'dst', 'dsfield_dscp', 'frag_offset', 'host', 'flags_rb', 'addr', 'len', 'src', 'checksum_bad', 'proto'],
			'http':['request', 'connection', 'content_length', 'request_version', 'expert', 'expert_severity', 'accept_language', 'content_type', 'request_uri', 'expert_group', 'request_full_uri', 'expert_message', 'accept', 'content_length_header', 'cache_control', 'request_method', 'user_agent', 'host'],
			'tcp':['checksum_bad', 'flags_urg', 'ack', 'options_type_class', 'analysis_bytes_in_flight', 'stream', 'options_type_number', 'seq', 'len', 'flags_res', 'option_len', 'analysis', 'hdr_len', 'dstport', 'flags_push', 'options_type_copy', 'window_size', 'flags_ns', 'flags_ack', 'flags_fin', 'option_kind', 'checksum_good', 'port', 'window_size_scalefactor', 'window_size_value', 'options_type', 'options', 'flags', 'flags_ecn', 'nxtseq', 'srcport', 'checksum', 'options_timestamp_tsval', 'flags_syn', 'flags_cwr', 'flags_reset', 'options_timestamp_tsecr'],
		}
		

	def createDataFromPcapfile(self,pcap_file):

		cap = pyshark.FileCapture(pcap_file,display_filter='http')

		w2log('this is cap:' + str(cap))

		try:

			w2log('now to load packets')

			cap.load_packets()

			w2log('loaded end')

			len_cap = len(cap)

			w2log('all length:'+str(len_cap))

			for j in range (len_cap):

				w2log('handing the No.'+str(j)+' File...')

				cur_data = {}

				#read each packet and write to db

				for item in self.pkt_struct:

					for i in self.pkt_struct[item]:

						cur_key = item+'_'+i

						if not item == 'pkt':

							cur_data[cur_key] = cap[j][item].get_field_value(i)

						else:#each layer info 

							cur_data[cur_key] = eval('cap[j].'+i)

				self.data[j] = cur_data

			sql = self.createSQL(self.data)

			# w2log(sql)

			self.wr2db(sql)

		except:

			w2log('load failed:'+str(sys.exc_info()[0]))

		return self.data

	def createSQL(self,all_data):

		w2log('alldata_type:'+str(type(all_data)))

		if all_data:

			values = ''

			for ite in all_data:

				data = all_data[ite]

				cur_value = '('

				for item in data:

					cur_value += '"' + str(data[item]) + '",'

				cur_value = cur_value[:-1] + '),'#delete last ","

				values = values + cur_value

			if values:

				self.sql = self.sql_header + values[:-1]#delete last ","

		else:

			w2log('no data accept')

		return self.sql

	def wr2db(self,sql ,host="manager_db",db="managerpress",username="managerpress",passwd="managerpress"):

		if sql:

			conn = mysql.connect(host,db,username,passwd)
			
			cursor = conn.cursor()

			try:

				w2log('now try to write to db')

				cursor.execute(sql)
				
				conn.commit()

				w2log('write to db success')

			except:

				w2log('fail to insert :' + str(sys.exc_info()[0]))

				conn.rollback()
			
			conn.close()
