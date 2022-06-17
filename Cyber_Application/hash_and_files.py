import requests
import argparse
import os
import time
import json
import hashlib


def checkhash(hsh):
    try:
        if len(hsh) == 32:
            return hsh
        elif len(hsh) == 40:
            return hsh
        elif len(hsh) == 64:
            return hsh
        else:
            print ("The Hash input does not appear valid.")
            exit()
    except Exception:
        print ('There is something wrong with your hash \n' + Exception)


def generatehash(filename):
   h = hashlib.sha1()
   with open(filename,'rb') as file:
       chunk = 0
       while chunk != b'':
           chunk = file.read(1024)
           h.update(chunk)
   return h.hexdigest()

def get_hash_info(hash):
    key = 'ebc3e70c4eedf7197c6af4f5466b63743b795d158053807fb8f2dac57f0c0ba8'
    params = {'apikey': key, 'resource': hash}
    url = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params)
    json_response = url.json()
    x = str(json_response)
    x = x.replace("'", '"')
    x = x.replace("False", '"False"')
    x = x.replace("True", '"True"')
    x = x.replace("None", '"None"')
    Final_output=[]
    parsed = json.loads(x)
    y =json.dumps(parsed, indent = 4, sort_keys=True)

    print ("\n")
    response = int(json_response.get('response_code'))
    if response == 0:
        print (y + "\n\n" + hash + ' is not in Virus Total')
        Final_output.append(y + "\n\n" + hash + ' is not in Virus Total')
        Final_output('\n')
    elif response == 1:
        positives = int(json_response.get('positives'))
        if positives == 0:
            print (y + "\n\n" + hash + ' is not malicious')
            Final_output.append(y + "\n\n" + hash + ' is not malicious')
            Final_output.append('\n')
        else:
            print (y + "\n\n" + hash + ' is malicious')
            Final_output.append(y + "\n\n" + hash + ' is a malicious hash. Hit Count:' + str(positives))
            Final_output.append('\n')
    else:
        print (y + "\n\n" + hash + ' could not be searched. Please try again later.')
        Final_output.append(y + "\n\n" + hash + ' could not be searched. Please try again later.')
    
    return Final_output
