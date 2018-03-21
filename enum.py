#!/usr/bin/env python
##############################################################################################################
## [Script]: hera.py -- Script for enumeration purpose
## [Autor]: Naivenom www.fwhibbit.es
##------------------------------------------------------------
## Script will be in constant update and incorporating new classes, including modes and sub-modes of operation
##############################################################################################################
import subprocess
import sys
import os
import time
import socket
import sys
import requests

class dns_():
	def __init__(self,iprange,out):
		self.iprange = iprange
		self.out = out
		
	def files(self):
		global out
		out = self.out
		try:
			os.stat(out)
		except:
			os.mkdir(out)
		print (chr(27) + "[1;31m" + "\n %s Doesn't exist, created %s" % (out,out) + chr(27) + "[0m")
	
	#GENERAL FUNCTIONS
	def hosts(self):
		rango = self.iprange
		self.files()
		global fhost
		fhost = out + "/hosts.txt"
		c = 0
		f = open(fhost, 'w')
		scan = "nmap -n -sP %s" % (rango)
		nmap = subprocess.check_output(scan, shell=True)
		lines = nmap.split("\n")
		print (chr(27) + "[1;32m" + "[+] Host in the network" + chr(27) + "[0m")
		for line in lines:
			line = line.strip()
			line = line.rstrip()
			if ("Nmap scan report for" in line):
				dir_IP = line.split(" ")[4]
				if (c > 0):
					f.write("%s" % (dir_IP))
					f.write('\n')
					print ("[*] %s" % (dir_IP))
			c += 1
		print (chr(27) + "[1;32m" + "[+] Found %s hosts" % (c) + chr(27) + "[0m")
		print (chr(27) + "[1;32m" + "[+] Created file in %s" % (fhost) + chr(27) + "[0m")
		f.close()
	
	def dns(self):	
		HostFile= open(fhost, 'r')
		fdns = out + "/dns.txt"
		DnsFile = open(fdns, 'w')
		c = 0
		print (chr(27) + "[1;32m" + "[+] Enumerating 53 TCP port to find DNS Servers" + chr(27) + "[0m")
		DnsFile.write("[+] Enumerating 53 TCP port to find DNS Servers")
		for dir_IP in HostFile:
			dir_IP = dir_IP.strip()
			scan1 = "nmap -n -sV -Pn -vv -p53 %s" % (dir_IP)
			nmap1 = subprocess.check_output(scan1, shell=True)
			lines = nmap1.split("\n")
			for line in lines:
				line = line.strip()
				line = line.rstrip()
				if ("53/tcp" in line) and ("open" in line) and ("open" in line) and not ("Discovered" in line):
					print (chr(27) + "[1;32m" + "[+] Including DNS Server %s in resolv.conf" % (dir_IP) + chr(27) + "[0m")
					resolv = open("/etc/resolv.conf", 'a')
					resolv.write("nameserver "+ dir_IP+"\n")
					resolv.close()
					DnsFile.write("[*] Found DNS Server in: %s/TCP" % (dir_IP))
					print ("\t[>>>] %s" % (line))
					DnsFile.write("\t[>] %s\n" % (line))
				c += 1
		DnsFile.write("\n")
		print (chr(27) + "[1;32m" + "[+] Found %s DNS Servers" % (c) + chr(27) + "[0m")
		DnsFile.write("[+] Found %s DNS Servers" % (c))
		HostFile.close()
		DnsFile.close()
		print (chr(27) + "[1;32m" + "[+] Locating Hosts name by IP" + chr(27) + "[0m")
		for ip in range(255):
			ipMod = self.iprange.split(".")
			ipMod.pop()
			str1 = '.'.join(ipMod)
			strIP = "."+str(ip)
			os.system("host %s" % (str1) +(strIP) + "| grep -v 'not found'")

class scan_:
	def __init__(self,ip,out):
		self.ip = ip
		self.out = out

	def files(self):
		global out
		out = self.out
		try:
			os.stat(out)
		except:
			os.mkdir(out)
		print (chr(27) + "[1;31m" + "\n %s Doesn't exist, created %s" % (out,out) + chr(27) + "[0m")

	def nmap_scan(self):
		self.files()
		fnmap = out + "/nmap.txt"
		NmapFile = open(fnmap, 'a')
		print (chr(27) + "[1;32m" + "[+] Quick Scanner:" + chr(27) + "[0m")
		scan = "nmap %s --top-ports 10 --open" % (self.ip)
		nmap = subprocess.check_output(scan, shell=True)
		lines = nmap.split("\n")
		for line in lines:
			line = line.strip()
			line = line.rstrip()
			array = line.split(" ")
			#print ("[*] %s" % (array))
			if ("report" in array):
				dir_IP = array[4:6]
				print ("[*] Hostname: %s" % (dir_IP))
				NmapFile.write("[*] Found Hostname: %s\n" % (dir_IP))
			elif ("open" in array):
				port = array[0]
				print ("[*] Open port: %s" % (port))
				NmapFile.write("[*] Found Open port: %s\n" % (port))
				services = array[-1]
				print ("[*] Service: %s" % (services))
				NmapFile.write("[*] Found Service: %s\n" % (services))
			elif ("MAC" in array):
				mac = array[2]	
				print ("[*] MAC address: %s" % (mac))
				NmapFile.write("[*] Found MAC Address: %s\n" % (mac))
		print (chr(27) + "[1;32m" + "[+] UDP slow scanner, it will take a long time:" + chr(27) + "[0m")
		opcionMenu = raw_input(chr(27) + "[1;33m" + "\t[!] Do you want to run this kind of scanner? (yes/no)" + chr(27) + "[0m")
		if opcionMenu == "yes":
			scan2 = "nmap -vv -Pn -A -sC --top-ports 200 -sU -T4 %s" % (self.ip)
			nmap2 = subprocess.check_output(scan2, shell=True)
			lines = nmap2.split("\n")
			for line in lines:
				line = line.strip()
				line = line.rstrip()
				array = line.split(" ")
				#print ("[*] %s" % (array))
				if ("open" and "udp-response"in array):
					dir_IP = array
					str1 = ' '.join(dir_IP)
					print(str(str1))
					NmapFile.write("[*] UDP Slow scanner: %s\n" % (str1))
		else:
			print (chr(27) + "[1;33m" + "\t[!] UDP slow scanner have not been executed " + chr(27) + "[0m")
		print (chr(27) + "[1;32m" + "[+] TCP slow scanner, it will take a long time:" + chr(27) + "[0m")
		opcionMenu = raw_input(chr(27) + "[1;33m" + "\t[!] Do you want to run this kind of scanner? (yes/no)" + chr(27) + "[0m")
		if opcionMenu == "yes":
			scan3 = "nmap -vv -Pn -sS -A -sC -p- -T4 %s" % (self.ip)
			nmap3 = subprocess.check_output(scan3, shell=True)
			lines = nmap3.split("\n")
			for line in lines:
				line = line.strip()
				line = line.rstrip()
				array = line.split(" ")
				#print ("[*] %s" % (array))
				if ("open" and "syn-ack"in array):
					dir_IP = array
					str1 = ' '.join(dir_IP)
					print(str(str1))
					NmapFile.write("[*] TCP Slow scanner: %s\n" % (str1))
		else:
			print (chr(27) + "[1;33m" + "\t[!] TCP slow scanner have not been executed " + chr(27) + "[0m")

class smb_:
	def __init__(self,ip,port,out):
		self.ip = ip
		self.port = port
		self.out = out

	def files(self):
		global out
		out = self.out
		try:
			os.stat(out)
		except:
			os.mkdir(out)
		print (chr(27) + "[1;31m" + "\n %s Doesn't exist, created %s" % (out,out) + chr(27) + "[0m")

	def smb_scan(self):
		self.files()
		fsmb = out + "/smb.txt"
		SmbFile = open(fsmb, 'a')
		print (chr(27) + "[1;32m" + "[+] Like auxiliary/scanner/smb/smb_enumshares (Metasploit)" + chr(27) + "[0m")
		print (chr(27) + "[1;32m" + "[+] Establish TCP Client Connect:" + chr(27) + "[0m")
		# Create a TCP/IP socket
		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

		# Connect the socket to the port where the server is listening
		server_address = (self.ip, int(self.port))
		print >>sys.stderr, 'connecting to %s port %s' % server_address
		sock.connect(server_address)
		try:
	
			# Send data protocol request
			data = ""
			data += "\x00\x00\x00\x54\xff\x53\x4d\x42\x72\x00\x00"
			data += "\x00\x00\x18\x01\x28\x00\x00\x00\x00\x00\x00\x00\x00"
			data += "\x00\x00\x00\x00\x00\x00\x58\x4d\x00\x00\x23"
			data += "\xd0\x00\x31\x00\x02\x4c\x41\x4e\x4d\x41"
			data += "\x4e\x31\x2e\x30\x00\x02\x4c\x4d\x31\x2e\x32\x58\x30"
			data += "\x30\x32\x00\x02\x4e\x54\x20\x4c\x41\x4e\x4d\x41\x4e"
			data += "\x20\x31\x2e\x30\x00\x02\x4e\x54\x20\x4c\x4d\x20\x30"
			data += "\x2e\x31\x32\x00"
			
			#print >>sys.stderr, 'sending>> "%s"' % data
			sock.sendall(data)

			# Look for the response
			amount_received = 0
			amount_expected = len(data)
	
			while amount_received < amount_expected:
				response = sock.recv(1024)
				amount_received += len(response)
				#print >>sys.stderr, 'received>> "%s"' % response
			
			# Send Session Setup And XRequest
			data = ""
			data += "\x00\x00\x00\x63\xff\x53\x4d\x42\x73\x00\x00\x00\x00\x18\x01\x20"
			data += "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x18\x0e"
			data += "\x00\x00\x16\x59\x0d\xff\x00\x00\x00\xdf\xff\x02\x00\x01\x00\xa2"
			data += "\x17\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x26"
			data += "\x00\x00\x2e\x00\x57\x69\x6e\x64\x6f\x77\x73\x20\x32\x30\x30\x30"
			data += "\x20\x32\x31\x39\x35\x00\x57\x69\x6e\x64\x6f\x77\x73\x20\x32\x30"
			data += "\x30\x30\x20\x35\x2e\x30\x00"

			#print >>sys.stderr, 'sending>> "%s"' % data1
			sock.sendall(data)

			# Look for the response
			amount_received1 = 0
			amount_expected1 = len(data)
	
			
			response = sock.recv(1024)
			amount_received1 += len(response)
			print >>sys.stderr, 'received>> "%s"' % response[-26:]
				
			
		finally:
			print >>sys.stderr, 'closing socket'
			sock.close()

class fuzzer_:
	def __init__(self,ip,wordlist,out):
		self.ip = ip
		self.wordlist = wordlist
		self.out = out

	def files(self):
		global out
		out = self.out
		try:
			os.stat(out)
		except:
			os.mkdir(out)
		print (chr(27) + "[1;31m" + "\n %s Doesn't exist, created %s" % (out,out) + chr(27) + "[0m")

	def fuzzer_web(self):
		self.files()
		ffuzzer = out + "/fuzzer.txt"
		FuzzerFile = open(ffuzzer, 'a')
		print (chr(27) + "[1;32m" + "[+] Web Fuzzer" + chr(27) + "[0m")
		opcionMenu = raw_input(chr(27) + "[1;33m" + "\t[!] Do you want to run Web File Extension Fuzzer? (yes/no)" + chr(27) + "[0m")
		
		if opcionMenu == "yes":
			extension = raw_input(chr(27) + "[1;33m" + "\t[!] Write file extension (Ex .php)" + chr(27) + "[0m")
		with open(self.wordlist, 'rU') as f:
			print (chr(27) + "[1;31m" + "\n [+] This will be take a long time" + chr(27) + "[0m")
			for line in f:
				if opcionMenu == "no":
					url = 'http://'+self.ip+"/"+line.strip("\n")+"/"
					
				elif opcionMenu == "yes":
					url = 'http://'+self.ip+"/"+line.strip("\n")+extension

				headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36'}
				result = requests.get(url, headers=headers)

				if result.status_code == 302:
					print (chr(27) + "[1;32m" + "[+]"+ url + chr(27) + "[0m")
					print "302 Found"
				elif result.status_code == 307:
					print (chr(27) + "[1;32m" + "[+]"+ url + chr(27) + "[0m")
					print "307 Temporary Redirect"
				elif result.status_code == 200:
					print (chr(27) + "[1;32m" + "[+]"+ url + chr(27) + "[0m")
					print "200 OK"
				elif result.status_code == 204:
					print (chr(27) + "[1;32m" + "[+]"+ url + chr(27) + "[0m")
					print "204 No Content"
				elif result.status_code == 301:
					print (chr(27) + "[1;32m" + "[+]"+ url + chr(27) + "[0m")
					print "301 Moved Permanently"
				elif result.status_code == 403:
					print (chr(27) + "[1;32m" + "[+]"+ url + chr(27) + "[0m")
					print "403 Forbidden"
		
		# Create a TCP/IP socket FUZZER (VERY SLOW-->BETTER REQUESTS LIB)
		'''client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		
		with open(self.wordlist, 'rU') as f:
			for line in f:
				if self.extension is None:
					server_address = (self.ip+"/"+line.strip("\n"), int(self.port))
				else:
					server_address = (self.ip+"/"+line.strip("\n")+self.extension, int(self.port))

				try:
					client_socket.connect(server_address)
					print(server_address)
					request_header = 'GET / HTTP/1.0\r\nHost: %s\r\n\r\n' % (self.ip)
					client_socket.send(request_header)

					response = ''
					while True:
						recv = client_socket.recv(1024)
						if not recv:
							break
						response += recv 

					print response
					client_socket.close() 
				except socket.gaierror, err:
					print(server_address)
					print "cannot resolve hostname: ", client_socket, err'''

	
class searchsploit_:
	def __init__(self,mode,arg_,arg1_,ext,out):
		self.mode = mode
		self.arg_ = arg_
		self.arg1_ = arg1_
		self.ext = ext
		self.out = out

	def files(self):
		global out
		out = self.out
		try:
			os.stat(out)
		except:
			os.mkdir(out)
		print (chr(27) + "[1;31m" + "\n %s Doesn't exist, created %s" % (out,out) + chr(27) + "[0m")

	def searchsploit(self):
		self.files()
		fvuln = out + "/vulnerability.txt"
		VulnFile= open(fvuln, 'a')
		if self.mode == "basic":
			print (chr(27) + "[1;32m" + "[+] Searchsploit" + chr(27) + "[0m")
			searchsploit_request = "searchsploit --colour -t %s %s | grep -vi '/dos/\|\%s[^$]'" % (self.arg_,self.arg1_,self.ext)
			searchsploit= subprocess.check_output(searchsploit_request, shell=True)
			lines = searchsploit.split("\n")
			for line in lines:
				line = line.strip()
				line = line.rstrip()
				array = line.split(" ")
				str1 = ' '.join(array)
				print(str(str1))
				VulnFile.write(str(str1)+"\n")
			print (chr(27) + "[1;32m" + "[+] Copy the Path if you want to use some exploit" + chr(27) + "[0m")
		elif self.mode == "filtered":	
			find = "."
			remplace = "\."
			filter_ = self.arg1_.replace(find,remplace)
			print (chr(27) + "[1;32m" + "[+] Searchsploit" + chr(27) + "[0m")
			searchsploit_request = "searchsploit --colour -t %s | grep -vi '/dos/\|\%s[^$]' | grep -i '%s'" % (self.arg_,self.ext,filter_)
			searchsploit= subprocess.check_output(searchsploit_request, shell=True)
			lines = searchsploit.split("\n")
			for line in lines:
				line = line.strip()
				line = line.rstrip()
				array = line.split(" ")
				str1 = ' '.join(array)
				print(str(str1))
				VulnFile.write(str(str1)+"\n")
			print (chr(27) + "[1;32m" + "[+] Copy the Path if you want to use some exploit" + chr(27) + "[0m")

		
