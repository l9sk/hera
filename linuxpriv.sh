#!/bin/bash
#Script for Linux Privilege Escalate
v="version 0.1"
#@naivenom


use () 
{ 
echo -e "\e[00;31m#\e[00m" "\e[00;33mLinux Privilege Escalate\e[00m" "\e[00;31m#\e[00m"
echo -e "\e[00;33m# www.fwhibbit.es / @naivenom \e[00m"
echo -e "\e[00;33m# $v\e[00m\n"
echo -e "\e[00;33m# Example: ./linuxpriv.sh -s advanced -m status"

		echo "OPTIONS:"
		echo "-m		Enter mode or option"
		echo "-h		Displays this help text"
		echo -e "\n"
		
}
start()
{
echo -e "\e[00;31m#\e[00m" "\e[00;33mLinux Privilege Escalate\e[00m" "\e[00;31m#\e[00m" 
echo -e "\e[00;33m# www.fwhibbit.es\e[00m" 
echo -e "\e[00;33m# @naivenom\e[00m" 
echo -e "\e[00;33m# It will include new features[00m\n" 
echo -e "\e[00;33m# $v\e[00m\n" 

}

options()
{
echo "Options:\n" 

if [ "$mode" ]; then 
	echo "mode = $mode" 
else 
	echo "No mode"
fi

if [ "$system" ]; then 
	echo "sudo =ENABLED" 
else 
	echo "sudo = DISABLED" 
fi

}

system_sudo()
{
	if [ "$mode" = "list" ]; then
		sudo -l | grep NOPASSWD
	else 
		:
	fi
	
}

linux_privilege()
{
	start
	options
	if [ "$system" = "sudo" ]; then
	system_sudo
	else 
		:
	fi

}

while getopts "s:m:h" option; do
 case "${option}" in
		s) system=${OPTARG};;
		m) mode=${OPTARG};;
		h) usage; exit;;
		*) usage; exit;;
 esac
done



linux_privilege
