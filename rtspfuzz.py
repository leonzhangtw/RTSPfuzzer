#!/usr/bin/python
# -*- coding: utf-8 -*-

import socket
import time
import os,sys
import csv
from ConfigParser import ConfigParser
from itertools import islice, product, chain
import string
import hashlib
from Payload import Payload
from copy import deepcopy
from random import *
import datetime


END = '\r\n'
TEST_CASE_ID = 0
OUTPUT_DATA = []

# send packet ,[!] Currently, no longer use this function
def go(data):
    global TEST_CASE_ID
    print("Payload : \n" + data)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        if SERVICETYPE == 'TCP':
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((RHOST, RPORT))
            print("Start Sent Test Case number: %d to the Target(%s,TCP: %d)!! " % (TEST_CASE_ID, RHOST, RPORT))
            s.send(data)
            print("Test Case number: %d Sented !!! " % (TEST_CASE_ID))
            TEST_CASE_ID += 1
            result = s.recv(1500)
            # raw_input("result")
            print("Server response:\n")
            print(result)
            time.sleep(DELAY)
        # UDP Socket
        else:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # UDP
            print("Start Sent Test Case number: %d to the Target(%s,UDP: %d)!! " % (TEST_CASE_ID, RHOST, RPORT))
            s.sendto(data, (RHOST, RPORT))
            print("Test Case number: %d Sented !!! " % (TEST_CASE_ID))
            print("udp result~~~~~")

            TEST_CASE_ID += 1

            time.sleep(DELAY)

    except socket.error, (value, message):
        if s:
            s.close()
        print('ERROR: Build Socket failed,Check Service is TCP or UDP !!!')
        print "Could not open socket: " + message
        sys.exit(1)

    file = open('LOG.TXT', 'a')
    file.write(data)
    file.close()
    # rcv = s.recv(1024)
    s.close()


# Functions to Craft Patterns Starts Here

"""
-------Automatic generate payload Center-------
--------------Advance mode---------------------
"""


def generate_payload_center():
    print("[*] Start generate payload to fuzz the target !")
    global TEST_CASE_ID,OUTPUT_DATA

    s = "socket"

    if SERVICETYPE == 'TCP':
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((RHOST, RPORT))
    else:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # UDP


    Csequence = 0
    # custom payload class
    rtsp_payload = Payload()

    PARAMETERS = ['OPTIONS',
                  'DESCRIBE',
                  'SETUP',
                  'PLAY',
                  'TEARDOWN',
                  'PAUSE']
    # PARAMETERS = ['OPTIONS']
    target_csv = createcsv()
    with open(target_csv ,'w') as output:
        writer = csv.writer(output)
        #Write header
        writer.writerow(['#','Payload','Response'])

        while TEST_CASE_ID < STOPAFTER:

            try:

                print("------------------Test case %s Start------------------------"%(TEST_CASE_ID))
                print("Start Time:%s"%(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
                print("Delay Time:%s/s"%(5))
                # clone a clean format
                payload_format = deepcopy(rtsp_payload.rtsp_payload_format)
     
                rand_payload_size = randint(STARTSIZE,ENDSIZE)
                # rand_payload_size = int(200)
                payload_format = rtsp_payload.random_generator_payload(payload_format, rand_payload_size,DEBUG)
                # payload_format = rtsp_payload.specific_generator_payload(payload_format,"cseq",rand_payload_size)
                # payload_format = rtsp_payload.specific_generator_payload(payload_format,"auth",rand_payload_size)
                if Csequence > 100:
                    Csequence = 0
                else:
                    Csequence += 1

                rand_method = choice(PARAMETERS)
                index = randint(0, 1)

                payload = advance_payload_generator(method=rand_method, index=index, Cseq=Csequence,
                                                    payload_format=payload_format)
                if SERVICETYPE == 'TCP':
                    s.send(payload)
                else:
                    s.sendto(payload)

                print("[-->]Advance Fuzzing Test case Sented! \nPayload is :\n" + payload)

                result = s.recv(1500)
                if result:
                    # while result:
                    result = result
                    print("[<--]Server Response:" + result)

                else:
                    result = '[<--]Server no response:!!!\n'
                    print("[<--]Server no response:!!!\n")
                buff_log = [TEST_CASE_ID,payload,result]
                print("End Time:%s"%(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
                print("------------------Test case %s End------------------------" % (TEST_CASE_ID))
                TEST_CASE_ID += 1
                # Write log to csv
                writer.writerow(buff_log)
                # DELAY
                time.sleep(DELAY)

            except KeyboardInterrupt:
                sys.exit()
            except socket.error, exc:
                print "[*]Caught exception socket.error : %s" % exc
                # create socket
                s.close()
                if SERVICETYPE == 'TCP':

                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.connect((RHOST, RPORT))
                else:
                    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # UDP


"""
Advace payload generator
"""

def advance_payload_generator(method, index, Cseq=1, payload_format=""):

    url = RTSP_TARGETURL
    slash = ""
    header_url = url
    # if method == "SETUP":
    #     header_url = url + '/track' + index
    #     slash = "/"
    #     url += slash
    # if method == "PLAY":
    #     slash = "/"
    #     url += slash
    #     header_url += slash

    buff = ''
    buff += '{method}{0[0]} {0[1]} {url}{0[2]} {0[3]} RTSP/1.0{0[4]}\r\n'.format(payload_format['header'],
                                                                                 method=method, url=header_url)
    buff += 'CSeq: {0[0]}{sequence_number}{0[1]} \r\n'.format(payload_format['cseq'], sequence_number=Cseq)

    # RTSP_AUTHORIZATION setting
    if RTSP_AUTHORIZATION == 'Y':
        response = computeKey(method=method, nonce=RTSP_NONCE, username=RTSP_USERNAME, realm=RTSP_REALM,
                          password=RTSP_PASSWORD, url=url)

        buff += 'Authorization: {0[0]}Digest {0[1]}username="{username}", {0[2]}realm="{realm}", {0[3]}nonce="{nonce}", {0[4]}uri="{url}", {0[5]}response="{response}" {0[6]}\r\n'.format(
            payload_format['auth'], username=RTSP_USERNAME,realm=RTSP_REALM, url=url,nonce=RTSP_NONCE, response=response)
    
    
    buff += "User-Agent: {0[0]}LibVLC/3.0.4 (LIVE555 Streaming Media v2016.11.28){0[1]}\r\n".format(
        payload_format['agent'])

    if method == 'DESCRIBE':
        buff += 'Accept: application / sdp\r\n'

    if method == 'SETUP':
        if index == "1":
            buff += 'Transport:{0[0]}RTP/AVP/TCP{0[1]};unicast{0[2]};interleaved=0-1{0[3]}\r\n'.format(
                payload_format['transport'])

        elif index == "2":
            buff += 'Transport:RTP/AVP/TCP{0[0]};unicast{0[1]};interleaved=2-3{0[2]}\r\n'.format(
                payload_format['transport'])
        buff += 'SESSION: {0[0]}{session}{0[1]}\r\n'.format(payload_format['session'], session=SESSION)

    if method == 'PLAY':
        buff += 'SESSION: {0[0]}{session}{0[1]}\r\n'.format(payload_format['session'], session=SESSION)
        buff += END
        buff += 'Range: {0[0]}npt=0.000{0[1]}-{0[2]}\r\n'.format(payload_format['range'])

    buff += END
    return buff




# Append the buffer size in LOG.TXT


def bufflen(bl):
    bl = str(bl)
    f = open('LOG.TXT', 'w')
    f.write("[*]  Buffer Length :")
    f.write(bl)
    f.write("\nRequest :\n")
    f.close()
def createcsv(): #將結果寫入成CSV檔，每一個csv檔結果
    outputRoute = './output'
    output_path = outputRoute 
    if not os.path.exists(output_path): #在這做if查詢, 確定沒有同名的檔案再建立
        os.makedirs(output_path) #利用os.makedirs()產生資料夾

    target_csv = output_path + "/RTSP_Result.csv"
    return target_csv

def writecsv(data): #將結果寫入成CSV檔，每一個csv檔結果
    # input('hi')
    #outputRoute Default Path: ./output
    with open(output_path + '/' + target_csv ,'wb') as output:

    # output = open(outputRoute + '\\' + target_csv ,'w',encoding = 'utf-8')
        writer = csv.writer(output)
        #Write header
        writer.writerow('#,Payload,Response\n')

        #編號,Payload,Response
        writer.writerow(data)
        # raw_input(output_path + '/' + target_csv)
        output.close()

# create Payload Pattern
def createpattern(length):
    length = int(length)
    data = ''.join(tuple(islice(chain.from_iterable(product(
        string.ascii_uppercase, string.ascii_lowercase, string.digits)), length)))
    return data

# comupute message digest authorization response key
def computeKey(method="", nonce="", username="", realm="", password="", url=""):
    if method is None:
        print("[*] Error , RTSP request needed a method")

    m1 = hashlib.md5(username + ":" + realm + ":" + password).hexdigest()
    m2 = hashlib.md5(method + ":" + url).hexdigest()
    response = hashlib.md5(m1 + ":" + nonce + ":" + m2).hexdigest()
    return response


# Global Start
config = ConfigParser()
config.read('rtsp.conf')
RHOST = config.get('rtspfuzz', 'RHOST')
RPORT = config.get('rtspfuzz', 'RPORT')
STARTSIZE = config.get('rtspfuzz', 'STARTSIZE')
ENDSIZE = config.get('rtspfuzz', 'ENDSIZE')
STEPSIZE = config.get('rtspfuzz', 'STEPSIZE')
STOPAFTER = config.get('rtspfuzz', 'STOPAFTER')
DELAY = config.get('rtspfuzz', 'DELAY')
SERVERPATH = config.get('rtspfuzz', 'SERVERPATH')
SESSION = config.get('rtspfuzz', 'SESSION')
junk = config.get('rtspfuzz', 'JUNK')
msfpat = config.get('rtspfuzz', 'MSFPATTERN')
SERVICETYPE = config.get('rtspfuzz', 'TYPE')
# RTSP authorization
RTSP_AUTHORIZATION = config.get('rtspfuzz','AUTHORIZATION')
RTSP_TARGETURL = config.get('rtspfuzz', 'TARGETURL')
RTSP_USERNAME = config.get('rtspfuzz', 'USERNAME')
RTSP_PASSWORD = config.get('rtspfuzz', 'PASSWORD')
RTSP_REALM = config.get('rtspfuzz', 'REALM')
RTSP_NONCE = config.get('rtspfuzz', 'NONCE')
# DEBUG mode
DEBUG = config.get('rtspfuzz', 'DEBUG')

# Little Bit Typecasting
RPORT = int(RPORT)
STARTSIZE = int(STARTSIZE)
ENDSIZE = int(ENDSIZE)
STEPSIZE = int(STEPSIZE)
STOPAFTER = int(STOPAFTER)
DELAY = int(DELAY)
# main function

if __name__ == "__main__":
    print "[*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*]"
    print "[*]                      WELCOME                   [*]"
    print "[*]                RTSPfuzzer version 1.0          [*]"
    print "[*]                rtsp Protocol fuzzer            [*]"
    print "[*]                Author :Leon Zhang              [*]"
    print "[*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*]"
    print "[*]              Your Preferences                     "
    print "[*] Target Host :", RHOST, "on PORT", RPORT
    print "[*] Start Size :", STARTSIZE
    print "[*] End Size :", ENDSIZE
    print "[*] Step Size :", STEPSIZE
    print "[*] Time Delay between two requests :", DELAY, "Sec"
    print "[*] Server path rtsp://", RHOST, "/", SERVERPATH
    print "[*] Session ID to use when required :", SESSION
    print "[*] Fuzzing with Metasploit Pattern :", msfpat
    print "[*]"
    print "[*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*]"
    print "[*] You are going to start fuzzing with Metasploit Pattern"
    raw_input("Ready to Start? (ctrl + c to exit)")
    print "[*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*]"
    print "[*]                  Starting Advanced fuzzing with Specially Crafted requests               [*]"
    print "[*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*]"

    generate_payload_center()

    print "[*] To see last successful request go to LOG.TXT file"
    print "[*] Exiting."
