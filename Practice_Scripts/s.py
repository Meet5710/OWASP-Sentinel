#!/usr/bin/python

from socket import *
import sys

tester=raw_input("ARE YOU SERVER OR CLIENT S/C : ")
if tester == "s" or tester == "server":

	ip=raw_input("\nYOUR IP : ")
	port=input("\nANY REGISTERED PORT : ")
	yourfrind=raw_input("\nYOUR NIC : ")
else:
	ip2=raw_input("\nYOUR FRIEND IP : ")
	port=input("\nYOUR FRIEND REGISTERED PORT : ")
	yourfrind=raw_input("\nYOUR NIC : ")
	

if tester == "s" or tester == "server":

	sock = socket(AF_INET, SOCK_STREAM)  
	sock.bind((ip, 6668)) 
	sock.listen(5)	
	while 1:
		conn, data = sock.accept()     
		conn.send('')
		
		while 1:   
			conn.send('')
			ashu=raw_input("\nYOU : ")
			aslam=" : "
			sedata=yourfrind+aslam+ashu			   
			conn.send(sedata)
			data = conn.recv(1024)
			print "\n",data 

else:

	sock = socket(AF_INET, SOCK_STREAM)
	try:
		sock.connect(('192.168.209.1', 6668))
	except:
		print 'CONNECTION ERROR'
	while 1:

		data = sock.recv(1024)
		print "\n",data
		toSend = raw_input('\nYOU : ')
		aslam=" : "
		sedata=yourfrind+aslam+toSend
		sock.send(sedata)











