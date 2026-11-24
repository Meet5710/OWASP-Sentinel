#!/usr/bin/env python
import smtplib, email, sys, time,StringIO,string, os, getpass,platform
from uuid import getnode as get_mac
if os.name == "posix":
	# Unix/Linux/MacOS/BSD/etc
	os.system('clear')
elif os.name in ("nt", "dos", "ce"):
	# DOS/Windows
	os.system('CLS')

print "\n\t\t#################################################"
print "\t\t#    FORENSIC SECURITY SHELL         	   #" 
print "\t\t#    Copyright (C) 2010 BY ASHIKALI             #"
print "\t\t#    GMAIL EMAIL SPAMMAR [POC]                  #" 
print "\t\t#    Ashikali1607[at]gmail[dot]com              #"                                
print "\t\t#    Xeniar Technology P Ltd(www.xeniartech.com)#" 
print "\t\t#    FOR GUJARAT POLICE ACEDEMY ONLY            #"
print "\t\t#################################################"
sender = raw_input("\nYOUR OWN GMAIL USERNAME : ")
passwd = raw_input("\nYOUR OWN GMAIL PASSWORD : ")
receiver = raw_input("\nEMAIL of RECEIVER : ")
subj = raw_input("\nSUBJECT: ")
bodyText = raw_input("\nMESSAGE : ")
num=input("Enter the Number of Email : ")
smtpHost = "smtp.gmail.com"
username = sender
port = 587 # ignored if no SMTP authentication is required
while(num!=0)

	rList = []
	rList = receiver.split(',');
	timegmt = time.gmtime(time.time( ))
	fmt = '%a, %d %b %Y %H:%M:%S GMT'
	datestr = time.strftime(fmt, timegmt)
	msg = 'From: %s\nTo: %s\nDate: %s\nSubject: %s\n%s' \
		% (sender, receiver, datestr, subj, bodyText)
	server = smtplib.SMTP(smtpHost, port)
	server.ehlo()
	server.starttls()
	server.ehlo()
	server.login(username, passwd)
	failed = server.sendmail(sender, rList, msg)
	server.quit() 
	num=num-1
