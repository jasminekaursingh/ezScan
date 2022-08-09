import sys
import os
import re
import nmap                         # import nmap.py module

try:
    nm = nmap.PortScanner()         # instantiate nmap.PortScanner object
except nmap.PortScannerError:
    print('Nmap not found', sys.exc_info()[0])
    sys.exit(1)
except:
    print("Unexpected error:", sys.exc_info()[0])
    sys.exit(1)

#Running discovery scan
nm.scan(arguments='-R -PE -PP -PM -PO -PU -PY80,23,443,21,22,25,3389,110,445,139 -PS80,23,443,21,22,25,3389,110,445,139,143,53,135,3306,8080,1723,111,995,993,5900,1025,587,8888,199,1720,465,548,113,81,6001,10000,514,5060,179,1026,2000,8443,8000,32768,554,26,1433,49152,2001,515,8008,49154,1027,5666,646 -iL ./hosts.txt')

print(nm.all_hosts())
for host in nm.all_hosts():
    print('----------------------------------------------------')
    print('Host : %s (%s)' % (host, nm[host].hostname()))
    print('State : {0}'.format(nm[host].state()))

#Creates additional directory to store hosts by ports file for later usage
newpath = r'./hostsByPort'
if not os.path.exists(newpath):
	os.makedirs(newpath)
	
newpath = r'./scanOutputs'
if not os.path.exists(newpath):
	os.makedirs(newpath)

#Outputting discovery scan to csv for further parsing
def output_csv(filename):
	#may not need nested function, but this works for now?
	def save_csv_data(nm_csv, path='./scanOutputs'):
		with open(path + '%s' % filename, 'w') as output:
			output.write(nm_csv)
	if (len(sys.argv) > 1 and sys.argv[1]):
    		save_csv_data(nm.csv(), path=sys.argv[1])
	else:
    		save_csv_data(nm.csv())

#Discovery scan outputted to csv
output_csv('/discoveryScan.csv')

#Parsing discovery scan to break up hosts in separate files for which ports they have open
#Mitigates running unnecessry hosts through additional scans
def writeHostsByPort(port):
	with open('./scanOutputs/discoveryScan.csv', 'r') as f:
		for line in f.readlines():
			x = re.compile('%s;.*;open;' %port)
			matches = x.finditer(line)
			for match in matches:
				with open("./hostsByPort/%s_hosts.txt" %port, "a") as o:
					IPs = re.findall("\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", line)[0]
					o.write("%s\n" % IPs)
					
#creating a string array of ports that were used in discovery scan to iterate through writing hosts by their open ports								
ports = ['80','23','443','21','22','25','3389','110','445','139','143','53','135','3306','8080','1723','111','995','993','5900','1025','587','8888','199','1720','465','548','113','81','6001','10000','514','5060','179','1026','2000','8443','8000','32768','554','26','1433','49152','2001','515','8008','49154','1027','5666','646','5357']

for x in ports:
	writeHostsByPort(x)

#Checks if file exists for hosts with specific open port number before running through script scan        		
if(os.path.exists('./hostsByPort/445_hosts.txt')):
	#First vuln scan for ms08_067
	nm.scan(arguments='-p445 --script smb-vuln-ms08-067 -Pn -iL ./hostsByPort/445_hosts.txt')
	output_csv('/ms08-067.csv')

	#Second vuln scan for eternal blue
	nm.scan(arguments='-p445 --script smb-vuln-ms17-010 -Pn -iL ./hostsByPort/445_hosts.txt')
	output_csv('/ms17_10.csv')

	#Third scan for writable unauth smb shares
	#You may supply smb share creds with adding --script-args 'smbdomain=DOMAIN,smbusername=USER,smbpassword=PASSWORD'
	nm.scan(arguments='-p445 --script smb-enum-shares -Pn -iL ./hostsByPort/445_hosts.txt')
	output_csv('/p445_smb_output.csv')

if(os.path.exists('./hostsByPort/139_hosts.txt')):
	nm.scan(arguments='-p139 --script smb-enum-shares -Pn -iL ./hostsByPort/139_hosts.txt')
	output_csv('/p139_smb_output.csv')

	#Fourth scan for writable WebDAV shares
if(os.path.exists('./hostsByPort/80_hosts.txt')):
	nm.scan(arguments='-p80 --script http-webdav-scan -Pn -iL ./hostsByPort/80_hosts.txt')
	output_csv('./scanOutputs/p80_webdav_output.csv')
	
if(os.path.exists('./hostsByPort/8080_hosts.txt')):
	nm.scan(arguments='-p8080 --script http-webdav-scan -Pn -iL ./hostsByPort/8080_hosts.txt')
	output_csv('/p8080_webdav_output.csv')

if(os.path.exists('./hostsByPort/443_hosts.txt')):
	nm.scan(arguments='-p443 --script http-webdav-scan -Pn -iL ./hostsByPort/443_hosts.txt')
	output_csv('/p443_webdav_output.csv')

if(os.path.exists('./hostsByPort/8443_hosts.txt')):
	nm.scan(arguments='-p8443 --script http-webdav-scan -Pn -iL ./hostsByPort/8443_hosts.txt')
	output_csv('/p8443_webdav_output.csv')
	
