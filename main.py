import requests
import json
import telnetlib
import time
import re

# checking AbuseIPDB Score for a given IP address
def abuseIP(ip):

    # Defining the api-endpoint
    url = 'https://api.abuseipdb.com/api/v2/check'

    querystring = {
        'ipAddress': ip,
        'maxAgeInDays': '90'
    }

    headers = {
        'Accept': 'application/json',
        'Key': '18a1d0629f4e14eaf1be102fb54cb877aadcdc5f9cbfb808ce7495953b19135287622ca7d9b08e55'
    }

    response = requests.request(method='GET', url=url, headers=headers, params=querystring)

    # Formatted output
    decodedResponse = json.loads(response.text)
    # print (json.dumps(decodedResponse, sort_keys=True, indent=4))

    abuseConfidenceScore = (decodedResponse["data"]["abuseConfidenceScore"])
    return abuseConfidenceScore

# getting hosts IP list from mikrotik router Packet Sniffer tool via telnet
def mikrotikTelnet(routerIP,user,password):
    dev_ip = routerIP
    USER = user
    PASSWORD = password
    comm1 = "/tool sniffer host print"

    tn = telnetlib.Telnet(dev_ip, timeout=1)
    tn.read_until(b"Login: ")
    tn.write(USER.encode("ascii") + b'\n')
    tn.read_until(b"Password: ")
    tn.write(PASSWORD.encode("ascii") + b'\n')
    tn.read_until(b">")
    time.sleep(1)
    tn.write(comm1.encode("ascii") + b"\r\n")
    time.sleep(1)
    Showcmdoutput = tn.read_very_eager().decode('ascii')
    tn.close()
    return Showcmdoutput

# find IP address in the returned telnet hosts string
hostsList = mikrotikTelnet("192.168.88.1", "admin", "")
ipPattern = re.compile('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
findIP = re.findall(ipPattern, hostsList)

# print list of hosts IP's with their abuse score
print("AbuseIPDB Score for hosts that were participating \n in data excange with Mikrotik home network router")
for x in findIP:
    print(x , " AbuseIPDB Score: ", abuseIP(x))
