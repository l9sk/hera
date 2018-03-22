#!/usr/bin/env python
#######################################################################
## [Script]: hera.py -- Script for Red Team purpose
## [Autor]: Naivenom www.fwhibbit.es
##------------------------------------------------------------
## The Script will be in constant update and incorporating new classes
#######################################################################
from enum import *
from cmd import Cmd
fhost = ""
out = ""
def logo():  # LOGO
	print (chr(27) + "[1;31m" + """
                               
,--.                            
|  ,---.  ,---. ,--.--. ,--,--. 
|  .-.  || .-. :|  .--'' ,-.  | 
|  | |  |\   --.|  |   \ '-'  | 
`--' `--' `----'`--'    `--`--' 
                               
""" + chr(27) + "[0m")
	print (chr(27) + "[0;33m" + " ::::::::::::::::::::::::::::::::::::::: v0.1  Author: Naivenom\n" + chr(27) + "[0m")
	print (chr(27) + "[0;33m" + " For Red Team learning purpose 'From discipline and sufferance comes freedom'\n" + chr(27) + "[0m")

class hera(Cmd):

	def do_dns(self, args):
		if len(args) == 0:
			print ("\nUsage: <parameter>\n")
			sys.exit(0)
		else:
			arg = args.split(" ")
			iprange = arg[0]
			out = arg[1]
		_dns_ = dns_(iprange,out)
		_dns_.hosts()
		_dns_.dns()

	def do_scan(self, args):
		if len(args) == 0:
			print ("\nUsage: <parameter>\n")
			sys.exit(0)
		else:
			arg = args.split(" ")
			ip = arg[0]
			out = arg[1]
		_scan_ = scan_(ip,out)
		_scan_.nmap_scan()

	def do_smb(self, args):
		if len(args) == 0:
			print ("\nUsage: <parameter>\n")
			sys.exit(0)
		else:
			arg = args.split(" ")
			ip = arg[0]
			port = arg[1]
			out = arg[2]
		_smb_ = smb_(ip,port,out)
		_smb_.smb_scan()

	def do_fuzzer(self, args):
		if len(args) == 0:
			print ("\nUsage: <parameter>\n")
			sys.exit(0)
		else:
			arg = args.split(" ")
			ip = arg[0]
			wordlist = arg[1]
			out = arg[2]
		_fuzzer_ = fuzzer_(ip,wordlist,out)
		_fuzzer_.fuzzer_web()

	def do_webproxy(self, args):
		if len(args) == 0:
			print ("\nUsage: <parameter>\n")
			sys.exit(0)
		else:
			arg = args.split(" ")
			ip = arg[0]
			mode = arg[1]
			out = arg[2]
		_webproxy_ = webproxy_(ip,out)
		if mode == "intercept":
			_webproxy_.webproxy_intercept()
		elif mode == "request":
			_webproxy_.webproxy_request()
		elif mode == "repeater":
			_webproxy_.webproxy_repeater()


	def do_vuln(self, args):
		if len(args) == 0:
			print "\nUsage: <parameter>\n"
			sys.exit(0)
		else:
			arg = args.split(" ")
			mode = arg[0]
			arg_ = arg[1]
			arg1_ = arg[2]
			ext = arg[3]
			out = arg[4]
		_search_ = searchsploit_(mode,arg_,arg1_,ext,out)
		_search_.searchsploit()



	last_output = ''

	def do_shell(self, line):
		output = os.popen(line).read()
		print (output)
		self.last_output = output
			
	def do_quit(self, args):
		print ("Quitting.")
		raise SystemExit

	def help_dns(self):
		print (chr(27) + "[1;32m" + "[+] Use: dns <iprange> <output> Ex: dns 192.168.1.0-255 dir_out" + chr(27) + "[0m")

	def help_scan(self):
		print (chr(27) + "[1;32m" + "[+] Use: scan <ip> <output> Ex: scan 192.168.1.10 dir_out" + chr(27) + "[0m")

	def help_shell(self):
		print (chr(27) + "[1;32m" + "[+] Use: shell <command> Ex: shell ls -la" + chr(27) + "[0m")

	def help_smb(self):
		print (chr(27) + "[1;32m" + "[+] Use: smb <ip> <port> <output> Ex: smb 192.168.1.104 139 dir_out" + chr(27) + "[0m")

	def help_fuzzer(self):
		print (chr(27) + "[1;32m" + "[+] Use: fuzzer <ip> <wordlist> <output> Ex: fuzzer 192.168.1.104 /usr/share/wordlists/dirb/small.txt / dir_out" + chr(27) + "[0m")

	def help_webproxy(self):
		print (chr(27) + "[1;32m" + "[+] Use: webproxy <ip webserver> <mode> <output> Ex: webproxy 192.168.1.104 intercept dir_out" + chr(27) + "[0m")
		print (chr(27) + "[1;32m" + "[+] Use: webproxy <ip webserver> <mode> <output> Ex: webproxy 127.0.0.1:8050 request dir_out" + chr(27) + "[0m")
		print (chr(27) + "[1;32m" + "[+] Use: webproxy <ip webserver> <mode> <output> Ex: webproxy 127.0.0.1:8050 repeater dir_out" + chr(27) + "[0m")
		print('''Mode:
			intercept
			request
			repeater''')

	def help_vuln(self):
		print (chr(27) + "[1;32m" + "[+] Use: vuln <mode> <software|arg> <version|arg1> <extension_exploit> <output>" + chr(27) + "[0m")
		print('''Examples of use:
			vuln filtered php 5.x .php dir_out
			vuln basic Apache mod_cgi .py dir_out''')

	def help_quit(self):
		print (chr(27) + "[1;32m" + "[+] Exit" + chr(27) + "[0m")


################################ M A I N #################################
if __name__ == '__main__':
	logo()
	prompt = hera()
	prompt.prompt = 'hera> '
	prompt.cmdloop('Red Team command line tool')
	
