#!/usr/bin/env python
import os 
import subprocess 
import sys
import requests 
import json
import csv
import requests
import json
import urllib2
import urllib
import webbrowser
import time
import re
from pprint import pprint
from termcolor import colored 
# dont know if this is the right way to do this - dafuq!!
#global pcap
#API keys for things
api_key = 'enterapikeyhere'
api_url = 'https://www.virustotal.com/vtapi/v2/'

#runcommands
#class RunCmd(object):
	#def cmd_run(self, cmd):
        #	self.cmd = cmd
        #	subprocess.call(self.cmd, shell=True)
	#a = RunCMD()

##### NETWORK MINer#####
def nm():
	print " " 
	os.chdir("/opt/NetworkMiner/") 
	pwd = os.system("pwd")
	opennm = raw_input(colored("Do you have a pcap? y or n: ", 'blue', attrs=['bold']))
	if opennm == "y":
		os.system("mono ./NetworkMiner.exe" + pcap + "&")
		time.sleep(3)
		menu()
	elif opennm == "n": 
		os.system("mono ./NetworkMiner.exe" + "&")
		time.sleep(3)
		menu()
	else:
		menu()

#####CAP TIPPER#### 
def cp():
	#global pcap
	print " " 
	os.chdir("/opt/CapTipper")
	os.system("pwd")
	os.system("clear")
	print colored("Select One of the following options", 'green')
	print " " 
	print colored("1. JSON and HTML Report", 'yellow') 
	print colored("2. Dump all Files from PCAP and exit", 'yellow') 
	print colored("3. Start CAPTipper with webserver", 'yellow')
	print colored("4. Start Captipper without websever", 'yellow')
	print colored("5. Exit", 'red')
	print " " 
	choice=raw_input(colored("Enter choice [1-5]: " , 'cyan', attrs=['bold']))
	if choice== "1": 
		print colored("JSON and HTML Report", 'yellow')
		report = raw_input(colored("Enter location to save report to: ", 'cyan', attrs=['bold']))
#		os.system("gnome-terminal -e" "python CapTipper.py " + pcap + " -r" + report)  
		if len(report) > 0: 
			subprocess.call(['gnome-terminal', '-e', 'python /opt/CapTipper/CapTipper.py '+pcap+' -r '+report])
			menu()
		else: 
			cp()
	elif choice=="2":
		print colored("Dump all Files from PCAP and exit", 'yellow')
		files = raw_input(colored("Enter location to save files: ", 'cyan', attrs=['bold'])) 
#		os.system("python CapTipper.py " + pcap + " -d" + files + " &")
		if len(files) > 0:
			subprocess.call(['gnome-terminal', '-e', 'python /opt/CapTipper/CapTipper.py '+pcap+' -d '+files])
			menu()
		else:
			cp()
	elif choice=="3":
		print colored("Start CAPTipper with webserver", 'yellow')
		#os.system("python CapTipper.py " + pcap + " &")
		subprocess.call(['gnome-terminal', '-e', 'sudo python /opt/CapTipper/CapTipper.py -p 8080 '+pcap])
		menu()
	elif choice=="4":
		print colored("Start Captipper without websever", 'yellow') 
		#subprocess.call("python CapTipper.py " + pcap + " -s", shell=True)
		#print os.system("pwd") 
		subprocess.call(['gnome-terminal', '-e', 'python /opt/CapTipper/CapTipper.py '+pcap+' -s'])
		menu()
	elif choice=="5":
		print colored("Exiting to main menu", 'red')
		menu()
	else: 
		raw_input(colored("Wrong option selected, Press \"enter\" to reset: ", 'red'))
		cp()
##### virus Total#### 
def vtfile():
	print " " 
	url = api_url + "file/scan"
    	file = raw_input("enterfile: ")
   	files = {'file': open(file, 'rb')}
   	headers = {"apikey": api_key}
    	response = requests.post( url, files=files, data=headers)
        xjson = response.json()
        response_code1 = xjson ['response_code']
        resource = xjson['resource']
        verbose_msg = xjson ['verbose_msg']
        permalink = xjson['permalink']
        print colored(verbose_msg, 'yellow')
#def vtget(): 
	if response_code1 == 1:
        	#print "code1:"
                #print "Openeing Report in Browser"
                url1 = api_url + "file/report"
                values = {'apikey': api_key,
                        'resource': resource}
                #webbrowser.open_new(permalink)
                #url1 = url + "/report"
                #print url1
                #print values
                results = requests.post(url1, values)
                #print results
                xjson2 = results.json()
        	response_code2 = xjson2['response_code']
        	permalink2 = xjson2['permalink']
        	scan_date2 = xjson2['scan_date']
        	scans = xjson2['scans']
        	#print response_code2
        	#print scans
                #print xjson2
                if response_code2 == 0:
            		t = 300
            		while t:
                		mins, secs = divmod(t, 60)
                    		timeformat = '{:02d}:{:02d}'.format(mins, secs)
                    		print(timleformat)
                    		time.sleep(1)
                    		t -= 1
        	elif response_code2 == 1: 
            		permalink2 =  xjson2['permalink']
                        print colored(permalink2, 'cyan')
            		webo = raw_input(colored("Do you want to open the report in a browser?", 'green'))
            		if webo == 'y' or webo == 'Y':
                		webbrowser.open_new(permalink2)
            		else:
                                    #return results
                                       #print xjson2['scans']
                            #print "Permalink:" + permalink2
                                    #print xjson2
                        	print ("Permalink: " + permalink2 + ", " + "ScanDate: " +  scan_date2)
                        	for i in scans:
                              		print("%s: " % i),
                               		if (str(scans[i]['detected']) == "False"):
                                		print colored('Clean', 'green')
                            		else:
                                    		print colored('Malicious -- %s'
                                 		% str(scans[i]['result']),'red')
			print " " 
			end = raw_input(colored("PressEnter to return to the Main Menu", 'red', attrs=['blink', 'bold']))
			if len(end) == 0:
				menu()
			else: 
				print "code4"
		else:
			print "code3"
	else:
        	print "code2"
#vtfile()
def vturl():
	print " " 
    	url = api_url + "url/scan"
        urlopen = raw_input(colored("Enter URL: ", 'cyan', attrs=['bold']))
        if len(urlopen) > 0:
		#files = {'file': open(file, 'rb')}
        	headers = {'apikey': api_key, 'url': urlopen}
        	response = requests.post( url, data=headers)
        	xjson = response.json()
   		#print xjson
        	response_code1 = xjson ['response_code']
        	resource = xjson['resource']
        	verbose_msg = xjson ['verbose_msg']
        	permalink = xjson['permalink']
        	print colored(verbose_msg, 'yellow')
    		print colored("Need to wait or shit does not work!", 'grey', attrs=['bold'])
    		time.sleep(30)
#def vtget(): 
        	if response_code1 == 1:
        		#print "code1:"
                	#print "Openeing Report in Browser"
                	url1 = api_url + "url/report"
                	values = {'apikey': api_key,
                        	'resource': resource}
                	#webbrowser.open_new(permalink)
                	#url1 = url + "/report"
                	#print url1
                	#print values
                	results = requests.post(url1, values)
                	#print results
                	xjson2 = results.json()
                	response_code2 = xjson2['response_code']
                	permalink2 = xjson2['permalink']
                	scan_date2 = xjson2['scan_date']
                	scans = xjson2['scans']
			if response_code2 == 0:
                        	t = 300
                        	while t:
                                	mins, secs = divmod(t, 60)
                                	timeformat = '{:02d}:{:02d}'.format(mins, secs)
                                	print(timeformat)
                                	time.sleep(1)
                                	t -= 1
                	elif response_code2 == 1: 
                        	permalink2 =  xjson2['permalink']
                        	print colored(permalink2, 'cyan')
                        	webo = raw_input(colored("Do you want to open the report in a browser?", 'green', attrs=['bold']))
                        	if webo == 'y' or webo == 'Y':
                                	webbrowser.open_new(permalink2)
                        	else:
                                	        #return results
                                	        #print xjson2['scans']
                                	#print "Permalink:" + permalink2
                                	        #print xjson2
                                	print ("Permalink: " + permalink2 + ", " + "ScanDate: " +  scan_date2)
                                	for i in scans:
                                        	print("%s: " % i),
                                        	if (str(scans[i]['detected']) == "False"):
                                                	print colored('Clean', 'green')
                                        	else:
                                                	print colored('Malicious -- %s'
                                                	% str(scans[i]['result']),'red')
				print " " 
                        	end = raw_input(colored("PressEnter to return to the Main Menu", 'red', attrs=['blink', 'bold']))
                        	if len(end) == 0:
                                	menu()
                        	else: 
                                	print "code4"
                	else:
                        	print "code2"
		else: 
			print "code3"
	else:
		print " "
		print colored("Hello? McFly!... Did you forget to enter in something? Anybody out there?", 'white', 'on_red', attrs=['bold'])
		time.sleelp(3)
		menu() 
def vtip():
	print " " 
        urla = api_url + "ip-address/report"
        ip = raw_input(colored("Enter IP: ", 'cyan', attrs=['bold']))
	if len(ip) > 0:
        	#files = {'file': open(file, 'rb')}
        	values = {'ip': ip, 'apikey': api_key}
        	response = urllib.urlopen('%s?%s' % ( urla, urllib.urlencode(values))).read()
		#oxjson = json.loads(response)
        	xjson = json.loads(response)['detected_urls']
		#xjson2 = json.loads(response)['detected_downloaded_samples']
		print " " 
		#print oxjson
        	print colored(ip, 'yellow' , attrs=['bold'])
		print " "
        	for urls in xjson:
			reslts = str(urls)
			#print shit
			#urls = ('url: ' + shit['url'])
			#print this
			#time.sleep(5)
			re1='.*?'	# Non-greedy match on filler
			re2='((http|ftp|https):\/\/([\w_-]+(?:(?:\.[\w_-]+)+))([\w.,@?^=%&:/~+#-]*[\w@?^=%&/~+#-]))'	# Single Quote String 1
			re3='.*?'	# Non-greedy match on filler
			re4='(\d+)'	# Any Single Digit 1
			rg = re.compile(re1+re2+re3+re4,re.IGNORECASE|re.DOTALL)
			m = rg.search(reslts)
			#print m 
			if m:
				strng1=m.group(3)
				d1=m.group(5)
				print colored("url: "+strng1, 'yellow', attrs=['bold']) 
				print colored("positives: "+d1, 'red', attrs=['bold'])
				print " " 
		end1 = raw_input(colored("Would you like to return to the main menu?  y or n: ", 'cyan', attrs=['bold']))
                if end1 == "y" or end1 =="Y" : 
                	time.sleep(2)
                        menu()
            	else:  
			os.system('clear')
                	print colored("Enter in another IP address then:" , 'red', 'on_white') 
                        time.sleep(4)
                        vtip() 

		###########REGEX SUCKS!!!!!!!############
		#sample = raw_input(colored("Would you like to see the malicious samples found? enter: y or n: " ,  'cyan', attrs=['bold']))
		#if sample == "y" or sample == "Y":
		#	for shtin xjson2:
		#		hash = str(sha)
		#		print hash
		#		print "5"
		#		rea='.*?'
		#		reb='(\d+)'
		#		rec='.*?'
		#		red='(\[A-Fa-f0-9\]{64})'
		#		rga = re.compile(rea+reb+rec+red,re.IGNORECASE|re.DOTALL)
	                        #rga = re.compile(rec+red,re.IGNORECASE|re.DOTALL)
				#print rga
		#		ma = rga.search(hash)
		#		print ma
        	                #print m 
                #	        if ma:
                 #       	        print "1"
		#			strng2=ma.group(1)
                 #               	d2=ma.group(2)
		#			print strng2
		#			print d2
	else:	
		print " " 
		print colored("You Didn/'t Enter in An IP ADDRESS, Reading is HARD isn't it?", 'white', 'on_red', attrs=['bold'])
		time.sleep(3)
		menu()
###open wireshark####
def ws():
	if pcap == 1:
		print " "
		print colored("These aren't the droids you are looking for... --No PCAP-- Can't use this!!!", 'white', 'on_red', attrs=['bold'])
		print "Try Again!"
		menu()
	else:
		#print colored("These aren't the droids you are looking for... --No PCAP-- Can't use this!!!", 'white', 'on_red')
		print " "
		print colored("Opening " +pcap+ " with wireshark!", 'yellow')
		print " "
		subprocess.call(['gnome-terminal', '-e', 'sudo wireshark -r '+pcap])
		time.sleep(2)
		menu()
###securi#####
def si():
	print " " 
	mainurl = "https://sitecheck.sucuri.net/results/"
	url = raw_input(colored("Enter website to scan: ", 'cyan' , attrs=['bold']))
	furl = mainurl + url
	os.system("clear")
	print " "
	one = colored("Website you are scanning: ", 'green')
	two = colored(url, 'red') 
	print one + two
	time.sleep(2)
	webbrowser.open_new(furl)
	print " "
	print colored("Opps there goes Rabbit!", 'grey')
	time.sleep(5)
	menu()
###projecthoneypot######
#def phpt():



####malwr####
def malwr():
	os.system('clear')
	print " "
	mal = raw_input(colored(" Would you like to open the MALWR site to upload a file? enter Y or N: " , 'cyan', attrs=['bold'])) 
	if mal == "y" or mal == "Y": 
		print " "
		time.sleep(1)
		print colored("I could not get the api working for this so it just opens the website!...." , 'white', 'on_red' , attrs=['bold'])
		url="https://malwr.com/submission/"
		webbrowser.open_new(url)
		print "Going back to the Main Menu " 
		time.sleep(2)
		menu()
	else: 
		print " " 
		print "Back to the Menu!" 
		time.sleep(1) 
		menu()
	##########THIS DIDNT WORK##############
	#files = raw_input("Enter File: ")
	#response = os.system("curl -F api_key=0a59587756eb44cdb0cde4acc4fb9f9f -F shared=yes -F file=files https://malwr.com/api/analysis/add/")
	#url = "https://malwr.com/api/analysis/add/"
	#data = '{"api_key": "api_key=0a59587756eb44cdb0cde4acc4fb9f9f", files=files}'
	#req = urllib.Request(url, data)
	#o = urllib.urlopen(req)
	#for i in o: 
	#	print (i)
	#o.close()	
	#print response
###url unshorten####
def us():
	#url = "https://unshorten.me/raw/"
	su = raw_input(colored("Enter in shorten-d URL: " , 'cyan', attrs=['bold']))
	hdr = {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.11 (KHTML, like Gecko) Chrome/23.0.1271.64 Safari/537.11',
         'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
         'Accept-Charset': 'ISO-8859-1,utf-8;q=0.7,*;q=0.3',
         'Accept-Encoding': 'none',
         'Accept-Language': 'en-US,en;q=0.8',
         'Connection': 'keep-alive'}
	iurl = "https://unshorten.me/json/"+su
	print iurl
	if len(su) > 0:
 		print " "
		#response = requests.post(iurl, data=hdr)
		#xjson = json.loads(response)
		#print xjson
		req = urllib2.Request(iurl, headers=hdr)
		response = urllib2.urlopen(req)
		#xjson = json.loads(response)
		#print xjson
		print response.read()
		#find = response.read()
		#print find['resolved_url': ]
		#print urls
		end = raw_input(colored("Would you like to enter another url or bo back to the menu, type 1 to try again or 2 for the menu: ", 'cyan', attrs=['bold']))
		if end == "1":
			print "Trying another url!!"
			us()
		else: 
			print " Back to the Menu"
			menu()
		
	else: 
		print "Something went wrong!... hmmm???? "
		print "Do you wnat to try again or go back to the menu?"
		end = raw_input(colored("Type 1 to try again or 2 for the menu", 'cyan', attrs=['bold']))
		if end == "1":
			print " " 
			print "Trying Again..."
			time.sleep(1)
			us() 
		else:
			print " " 
			print "Back to the Menu"
			time.sleep(1)
			menu()
#urlquer
def uq():
	print " " 
	print colored("This will open urlquery.net into a webbrowser", 'yellow', attrs=['bold'])
	webbrowser.open_new("https://urlquery.net/")
	os.system('clear')
	print "Have fun! Returning to the Menu..."
	time.sleep(3)
	menu()

###main###
def menu(): 
	print " " 
	print colored("------------- Network Forensics Tools -------------", 'yellow', 'on_magenta', attrs=['bold'])
	print " "
	print 5 * "#", " 1-8 are the only ones working right now!!! ", 5 * "#"
	print " "
	time.sleep(1)
	os.system('clear')
	print colored("------------- Network Forensics Tools -------------", 'yellow', 'on_magenta', attrs=['bold'])
	print " "
	print colored("1. NetworkMiner", 'cyan', attrs=['bold'])
	print colored("2. CapTipper", 'cyan', attrs=['bold'])
	print colored("3. VT file", 'cyan', attrs=['bold'])
	print colored("4. VT URL", 'cyan', attrs=['bold'])
	print colored("5. VT IP", 'cyan', attrs=['bold'])
	print colored("6. Wireshark", 'cyan', attrs=['bold'])
	print colored("7. Securi", 'cyan', attrs=['bold'])
	print colored("8. urlquery", 'cyan', attrs=['bold'])
	print colored("9. Malwr" , 'cyan', attrs=['bold'])
	print colored("10. URL-UnShorten", 'cyan', attrs=['bold']) 
	print colored("11. EXIT", 'cyan', 'on_red', attrs=['bold'])

	#loop=True 
	#while loop: 
	#	menu()
	print " "
	print colored("Remeber! ** Captipper AND WireShark will not work without a PCAP! Gawd, Tina...", 'white' , 'on_red',  attrs=['bold', 'blink'])
	print " "
	choice=raw_input("Enter choice [1-11]: ")
	#print " " 
	#print colored("Remeber!! ** Captipper AND WireShark  won't work without a PCAP!...Gawd!, Tina. ", 'white' , 'on_red',  attrs=['bold', 'blink'])
	if choice == "1":
		os.system('clear')
		print colored("Selected: NetworkMiner", 'yellow', attrs=['bold']) 
		nm()
		#os.system('clear')
	elif choice == "2":
		os.system('clear')
		print colored("Selected: CapTipper" , 'yellow', attrs=['bold']) 
		cp()
		#os.system('clear')
	elif choice == "3":
		os.system('clear')
		print colored("Selected: VT file", 'yellow', attrs=['bold'])
		vtfile()
		#os.system('clear')
	elif choice == "4":
		os.system('clear')
		print colored("Selected: VT URL", "yellow", attrs=['bold'])
		vturl()
	elif choice == "5":
		os.system('clear')
		print colored("Selected: VT IP", 'yellow', attrs=['bold'])
		vtip()
	elif choice == "6":
		os.system('clear')
		print colored("Selected: Wireshark", 'yellow', attrs=['bold'])
		ws()
		#os.system('clear')
	elif choice == "7":
		os.system('clear')
		print colored("Selected: Securi", 'yellow', attrs=['bold'])
		#time.sleep(2)
		si()
		os.system('clear')
	elif choice == "8":
		os.system('clear')
		print colored("Selected: urlquery", 'yellow', attrs=['bold'])
		uq()
		#os.system('clear')
	elif choice == "9":
		print colored("Selected: Malwr", 'yellow', attrs=['bold'])
		malwr()
		os.system('clear')
	elif choice == "10":
		os.system('clear')
		print colored("Selected: url-UnShorten", 'yellow', attrs=['bold']) 
		#time.sleep(2)
		#os.system('clear')
		us()
		#os.system('clear')
	elif choice == "11":
		os.system('clear')
		print colored("Don/'t start something, won/'t be nothing!" , 'red', 'on_white', attrs=['bold'])
		exit() 
			#loop=False
	else: 
		raw_input(colored("Wrong option selected, Press ENTER to reset", 'red', attrs=['bold']))
		menu()
#start this Whaaaaaat.....
os.system('clear')
print " " 
print  colored("-------------- Network Forensics Tools ------------" , 'yellow', 'on_magenta', attrs=['bold'])
print " " 
openprog = raw_input(colored("Do you have a pcap? y or n: ", 'cyan', attrs=['bold','blink']))
time.sleep(2)
os.system('clear')
global pcap
if openprog == "y":
	print " "
        pcap=raw_input(colored("Enter the Location of the PCAP: ", 'blue', attrs=['bold', 'blink']))
        menu()
else:
        print " "
	os.system('clear')
	#print colored("Captipper wont work without a PCAP!...Gawd! ", 'white' , 'on_red',  attrs=['bold', 'blink'])
	pcap = 1
        #print pcap
	menu()
print " "