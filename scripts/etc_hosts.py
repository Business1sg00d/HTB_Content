#!/usr/bin/python3

import re
import sys
import requests

# Check if root, if not then exit. Comment this out if you already have write permissions to /etc/hosts.
if __import__("os").getuid() != 0:
    print("Run as root; may need to append /etc/hosts.")
    exit(0)

# Command line argument
ip = str(sys.argv[1])

# Url to request
url = f'http://{ip}'

# Capturing errors
try:
    response = requests.get(url)
except requests.exceptions.ConnectionError as response:
    conn_error = response
except Exception:
    pass

# If the domain already resolves to /etc/hosts, then the above error handling doesn't instantiate variables.
# So just exit and perform enumeration as usual.
if "conn_error" not in locals():
    print("Good chance no domain name was found or resolution is occuring as should.")
    exit(0)

# Extract the domain name and port that the redirect is attempting.
if conn_error: 
    find_host = re.findall(r"host=.*?\)",str(conn_error))
    host = str(find_host[0].split(',')[0].split('host=')[1].strip('\''))
    port = find_host[0].split(',')[1].split('port=')[1].strip(')')
    domain = "http://"+host+':'+port
    print("Adding " + host + " to /etc/hosts.")

# Write the IP from argv[1] and the domain name found into /etc/hosts.
# IF ERRORS OCCUR AT THIS POINT OR AFTER, CHECK AND DELETE THE LAST LINE IN /etc/hosts.
with open("/etc/hosts", 'a') as w:
    if ':' in ip:
        ip = ip.split(':')[0]

    w.write(f"{ip} " + host)
    w.write('\n')

# Attempt the request again, but should resolve to /etc/hosts and give code 200
# unless something screwy is going on.
try:
    response = requests.get(url)
    print("Response code " + str(response.status_code) + " received. Try accessing " + domain + " in browser.")
except Exception as e:
    print(e)

