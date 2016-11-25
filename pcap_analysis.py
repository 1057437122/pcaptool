#!/usr/bin/python
import MySQLdb as mysql
import random
import threading
import time
import datetime
import pyshark


class PcapHandler:

	def __init__(self):

		self.data = {}

		self.sql = ''

		self.pkt_struct = {
			'pkt':['captured_length','length','sniff_time','sniff_timestamp','number','transport_layer'],
			'eth':['dst', 'lg', 'addr', 'ig', 'type', 'src'],
			'ip':['flags_mf', 'ttl', 'version', 'dst_host', 'flags_df', 'flags', 'dsfield', 'src_host', 'checksum_good', 'id', 'checksum', 'dsfield_ecn', 'hdr_len', 'dst', 'dsfield_dscp', 'frag_offset', 'host', 'flags_rb', 'addr', 'len', 'src', 'checksum_bad', 'proto'],
			'http':['request', 'connection', 'content_length', 'request_version', 'expert', 'expert_severity', 'accept_language', 'content_type', 'request_uri', 'expert_group', 'request_full_uri', 'expert_message', 'accept', 'content_length_header', 'cache_control', 'request_method', 'user_agent', 'host'],
			'tcp':['checksum_bad', 'flags_urg', 'ack', 'options_type_class', 'analysis_bytes_in_flight', 'stream', 'options_type_number', 'seq', 'len', 'flags_res', 'option_len', 'analysis', 'hdr_len', 'dstport', 'flags_push', 'options_type_copy', 'window_size', 'flags_ns', 'flags_ack', 'flags_fin', 'option_kind', 'checksum_good', 'port', 'window_size_scalefactor', 'window_size_value', 'options_type', 'options', 'flags', 'flags_ecn', 'nxtseq', 'srcport', 'checksum', 'options_timestamp_tsval', 'flags_syn', 'flags_cwr', 'flags_reset', 'options_timestamp_tsecr'],
		}
		

	def createDataFromPcapfile(self,pcap_file):

		cap = pyshark.FileCapture(pcap_file,display_filter='http')

		try:

			cap.load_packets()

			len_cap = len(cap)

			data = {}

			for j in range(len_cap):

				#read each packet and write to db

				for item in self.pkt_struct:

					for i in self.pkt_struct[item]:

						cur_key = item+'_'+i

						if not item == 'pkt':

							data[cur_key] = cap[j][item].get_field_value(i)

						else:#each layer info 

							data[cur_key] = eval('cap[j].'+i)


			self.data = data

		except:

			print 'load failed'

			self.data={}

		return self.data

	def createSQL(self,data):

		if data:

			sql = 'insert into pcap_packets ('

			column_name = ''

			column_value = ''

			for item in data:

				if not data[item] == '':

					column_name += item+','

					column_value += '"'+str(data[item])+'",'

			column_name = column_name[:-1]#delete last ,

			column_value = column_value[:-1]#delete last ","

			sql = sql+column_name+') values('+column_value+')'

			self.sql = sql

		return self.sql

	def wr2db(self,sql ,host="manager_db",db="managerpress",username="managerpress",passwd="managerpress"):

		conn = mysql.connect(host,db,username,passwd)
		
		cursor = conn.cursor()

		# print sql

		try:

			cursor.execute(sql)
			
			conn.commit()

		except:

			conn.rollback()
		
		conn.close()
