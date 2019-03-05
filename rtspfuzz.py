#!/usr/bin/python
# -*- coding: utf-8 -*-

import socket
import time
import sys
from ConfigParser import ConfigParser
from itertools import islice, product, chain
import string

END = '\r\n'
TEST_CASE_ID = 0

def go(data):
    global  TEST_CASE_ID
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        if SERVICETYPE == 'TCP':
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((RHOST, RPORT))
            print("Start Sent Test Case number: %d to the Target(%s,TCP: %d)!! " %(TEST_CASE_ID,RHOST,RPORT))
            s.send(data)
            print("Test Case number: %d Sented !!! " %(TEST_CASE_ID ))
            TEST_CASE_ID += 1 
            time.sleep(DELAY)
        else :
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # UDP
            print("Start Sent Test Case number: %d to the Target(%s,UDP: %d)!! " %(TEST_CASE_ID,RHOST,RPORT))
            s.sendto(data, (RHOST,RPORT))
            print("Test Case number: %d Sented !!! " %(TEST_CASE_ID ))
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


    
    # s.send(data)
    # s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # raw_input(bytes(MESSAGE, "utf-8"))
    # s.sendto(bytes(rtp, "utf-8"), (RHOST, RPORT))
    # s.sendto(rtp, (RHOST, RPORT))



# Functions to Craft Patterns Starts Here


def craft0(focus, size):
    print "[*]  -> Fuzzing ", focus, "Fuzzing size set to ", size, " (Basic crafting 0)"
    buff = ''
    buff += focus  # OPTIONS AAAAAAAAAAAAAAAAA\r\n
    buff += ''
    if msfpat == "ON":
        buff += createpattern(size)
    else:
        buff += junk*int(size)
    buff += END
    go(buff)


def craft1(focus, size):
    print "[*]  -> Fuzzing ", focus, "Fuzzing size set to ", size, " (Basic crafting 1)"
    buff = ''
    buff += focus  # OPTIONS rtsp://192.168.56.1/xpAAAAAAAAAAAAAAAAA RTSP/1.0
    buff += ' '  # CSeq: 1
    # User-Agent: VLC media player (LIVE555 Streaming Media v2010.02.10)
    buff += 'rtsp://'
    buff += RHOST
    buff += '/'
    buff += SERVERPATH
    if msfpat == "ON":
        buff += createpattern(size)
    else:
        buff += junk*int(size)
    buff += ' RTSP/1.0'
    buff += END
    buff += 'CSeq: 1'
    buff += END
    buff += "User-Agent: VLC media player (LIVE555 Streaming Media v2010.02.10)"
    buff += END
    buff += "\n"
    go(buff)


def craft2(focus, size):
    print "[*]  -> Fuzzing ", focus, "Fuzzing size set to ", size, " (Basic crafting 2)"
    buff = ''
    buff += focus  # OPTIONS rtsp://192.168.56.1/xp RTSP/1.0
    buff += ' '  # CSeq: 1
    # User-Agent: VLC media player (LIVE555 Streaming Media v2010.02.10)AAAAAAAAAAAAAAAAAAAAAAAAA
    buff += 'rtsp://'
    buff += RHOST
    buff += '/'
    buff += SERVERPATH
    buff += ' RTSP/1.0'
    buff += END
    buff += 'CSeq: 1'
    buff += END
    buff += 'User-Agent: VLC media player (LIVE555 Streaming Media v2010.02.10)'
    if msfpat == "ON":
        buff += createpattern(size)
    else:
        buff += junk*int(size)
    buff += END
    buff += "\n"
    go(buff)


def craft3(focus, size):
    print "[*]  -> Fuzzing ", focus, "Fuzzing size set to ", size, " (Basic crafting 3)"
    buff = ''
    buff += focus  # OPTIONS AAAAAAAAAAAAAAAAAAAAAA RTSP/1.0
    buff += ' '  # CSeq: 1
    # User-Agent: VLC media player (LIVE555 Streaming Media v2010.02.10)
    if msfpat == "ON":
        buff += createpattern(size)
    else:
        buff += junk*int(size)
    buff += ' RTSP/1.0'
    buff += END
    buff += 'CSeq: 1'
    buff += END
    buff += 'User-Agent: VLC media player (LIVE555 Streaming Media v2010.02.10)'
    buff += END
    buff += "\n"
    go(buff)


def craft4(focus, size):
    print "[*]  -> Fuzzing ", focus, "Fuzzing size set to ", size, " (Basic crafting 4)"
    buff = ''
    buff += focus  # OPTIONS rtsp://192.168.56.1/xp RTSP/1.0
    buff += ' '  # CSeq: AAAAAAAAAAAAAAAAAAAAAAAAA
    # User-Agent: VLC media player (LIVE555 Streaming Media v2010.02.10)
    buff += 'rtsp://'
    buff += RHOST
    buff += '/'
    buff += SERVERPATH
    buff += ' RTSP/1.0'
    buff += END
    buff += 'CSeq: '
    if msfpat == "ON":
        buff += createpattern(size)
    else:
        buff += junk*int(size)
    buff += END
    buff += 'User-Agent: VLC media player (LIVE555 Streaming Media v2010.02.10)'
    buff += END
    buff += "\n"
    go(buff)


# This fumction will always accept Describe as focus parameter and Sequence parameter will be always 2
def craft5(focus, size):
    print "[*]  -> Fuzzing ", focus, "Fuzzing size set to ", size, " (Advanced crafting 1)"
    buff = ''
    buff += focus  # DESCRIBE rtsp://192.168.56.1/xp RTSP/1.0
    buff += ' '  # CSeq: 2
    buff += 'rtsp://'  # Accept: application/sdpAAAAAAAAAAAAAAAAAAA
    # User-Agent: VLC media player (LIVE555 Streaming Media v2010.02.10)
    buff += RHOST
    buff += '/'
    buff += SERVERPATH
    buff += ' RTSP/1.0'
    buff += END
    buff += 'CSeq: 2'
    buff += END
    buff += 'Accept: '
    buff += 'application/sdp'
    if msfpat == "ON":
        buff += createpattern(size)
    else:
        buff += junk*int(size)
    buff += END
    buff += "User-Agent: VLC media player (LIVE555 Streaming Media v2010.02.10)"
    buff += END
    buff += "\n"
    go(buff)

# SETUP rtsp://server.com:554/xp/trackID=0 RTSP/1.0
# CSeq: 3
# Transport: RTP/AVP;unicast;client_port=36142-36143
# User-Agent: VLC media player (LIVE555 Streaming Media v2010.02.10)


def craft6(focus, size):
    print "[*]  -> Fuzzing ", focus, "Fuzzing size set to ", size, " (Advanced crafting 2)"
    buff = ''
    buff += focus
    buff += ' '
    buff += 'rtsp://'
    buff += RHOST
    buff += '/'
    buff += SERVERPATH
    buff += ' RTSP/1.0'
    buff += END
    buff += 'CSeq: 3'
    buff += END
    buff += 'Transport: '
    if msfpat == "ON":
        buff += createpattern(size)
    else:
        buff += junk*int(size)
    buff += '/'
    buff += 'AVP;unicast;client_port=36142-36143'
    buff += END
    buff += "User-Agent: VLC media player (LIVE555 Streaming Media v2010.02.10)"
    buff += END
    buff += "\n"
    go(buff)


def craft7(focus, size):
    print "[*]  -> Fuzzing ", focus, "Fuzzing size set to ", size, " (Advanced crafting 3)"
    buff = ''
    buff += focus  # Transport: RTP/AAAAAAAA;unicast;client_port=36142-36143
    buff += ' '
    buff += 'rtsp://'
    buff += RHOST
    buff += '/'
    buff += SERVERPATH
    buff += ' RTSP/1.0'
    buff += END
    buff += 'CSeq: 3'
    buff += END
    buff += 'Transport: RTP/'
    if msfpat == "ON":
        buff += createpattern(size)
    else:
        buff += junk*int(size)
    buff += ';'
    buff += 'unicast;client_port=36142-36143'
    buff += END
    buff += "User-Agent: VLC media player (LIVE555 Streaming Media v2010.02.10)"
    buff += END
    buff += "\n"
    go(buff)


def craft8(focus, size):
    print "[*]  -> Fuzzing ", focus, "Fuzzing size set to ", size, " (Advanced crafting 4)"
    buff = ''  # Transport: RTP/AVP;AAAAAAAAAAAAAAA;client_port=36142-36143
    buff += focus
    buff += ' '
    buff += 'rtsp://'
    buff += RHOST
    buff += '/'
    buff += SERVERPATH
    buff += ' RTSP/1.0'
    buff += END
    buff += 'CSeq: 3'
    buff += END
    buff += 'Transport: RTP/AVP;'
    if msfpat == "ON":
        buff += createpattern(size)
    else:
        buff += junk*int(size)
    buff += ';client_port=36142-36143'
    buff += END
    buff += "User-Agent: VLC media player (LIVE555 Streaming Media v2010.02.10)"
    buff += END
    buff += "\n"
    go(buff)


def craft9(focus, size):
    print "[*]  -> Fuzzing ", focus, "Fuzzing size set to ", size, " (Advanced crafting 5)"
    buff = ''  # Transport: RTP/AVP;unicast;client_port=AAAAAAAAAAAAAAAAAAAAAAAAAA-36143
    buff += focus
    buff += ' '
    buff += 'rtsp://'
    buff += RHOST
    buff += '/'
    buff += SERVERPATH
    buff += ' RTSP/1.0'
    buff += END
    buff += 'CSeq: 3'
    buff += END
    buff += 'Transport: RTP/AVP;unicast;client_port='
    if msfpat == "ON":
        buff += createpattern(size)
    else:
        buff += junk*int(size)
    buff += '-36143'
    buff += END
    buff += "User-Agent: VLC media player (LIVE555 Streaming Media v2010.02.10)"
    buff += END
    buff += "\n"
    go(buff)


def craft10(focus, size):
    print "[*]  -> Fuzzing ", focus, "Fuzzing size set to ", size, " (Advanced crafting 6)"
    buff = ''  # Transport: RTP/AVP;unicast;client_port=36142-AAAAAAAAAAAAAAAAAAAAAAAAAAA
    buff += focus
    buff += ' '
    buff += 'rtsp://'
    buff += RHOST
    buff += '/'
    buff += SERVERPATH
    buff += ' RTSP/1.0'
    buff += END
    buff += 'CSeq: 3'
    buff += END
    buff += 'Transport: RTP/AVP;unicast;client_port=36142-'
    if msfpat == "ON":
        buff += createpattern(size)
    else:
        buff += junk*int(size)
    buff += END
    buff += "User-Agent: VLC media player (LIVE555 Streaming Media v2010.02.10)"
    buff += END
    buff += "\n"
    go(buff)
# GET_PARAMETER rtsp://server.com:554/xp RTSP/1.0
# CSeq: 6
# Session: e539b3f49ccf77ea
# User-Agent: VLC media player (LIVE555 Streaming Media v2010.02.10)


def craft11(focus, size):
    print "[*]  -> Fuzzing ", focus, "Fuzzing size set to ", size, " (Advanced crafting 7)"
    buff = ''
    buff += focus
    buff += ' '
    buff += 'rtsp://'
    buff += RHOST
    buff += '/'
    buff += SERVERPATH
    buff += ' RTSP/1.0'
    buff += END
    buff += 'CSeq: 6'
    buff += END
    buff += 'Session: '
    if msfpat == "ON":
        buff += createpattern(size)
    else:
        buff += junk*int(size)
    buff += END
    buff += "User-Agent: VLC media player (LIVE555 Streaming Media v2010.02.10)"
    buff += END
    buff += "\n"
    go(buff)
# TEARDOWN rtsp://server.com:554/xp RTSP/1.0
# CSeq: 7
# Session: e539b3f49ccf77ea
# User-Agent: VLC media player (LIVE555 Streaming Media v2010.02.10)


def craft12(focus, size):
    print "[*]  -> Fuzzing ", focus, "Fuzzing size set to ", size, " (Advanced crafting 8)"
    buff = ''
    buff += focus
    buff += ' '
    buff += 'rtsp://'
    buff += RHOST
    buff += '/'
    buff += SERVERPATH
    buff += ' RTSP/1.0'
    buff += END
    buff += 'CSeq: 7'
    buff += END
    buff += 'Session: '
    if msfpat == "ON":
        buff += createpattern(size)
    else:
        buff += junk*int(size)
    buff += END
    buff += "User-Agent: VLC media player (LIVE555 Streaming Media v2010.02.10)"
    buff += END
    buff += "\n"
    go(buff)

# PLAY rtsp://server.com:554/xp RTSP/1.0
# CSeq: 5
# Session: e539b3f49ccf77ea
# Range: npt=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
# User-Agent: VLC media player (LIVE555 Streaming Media v2010.02.10)


def craft13(focus, size):
    print "[*]  -> Fuzzing ", focus, "Fuzzing size set to ", size, " (Advanced crafting 8)"
    buff = ''
    buff += focus
    buff += ' '
    buff += 'rtsp://'
    buff += RHOST
    buff += '/'
    buff += SERVERPATH
    buff += ' RTSP/1.0'
    buff += END
    buff += 'CSeq: 7'
    buff += END
    buff += 'Session: '
    buff += SESSION
    buff += END
    buff += 'Range: npt='
    if msfpat == "ON":
        buff += createpattern(size)
    else:
        buff += junk*int(size)
    buff += END
    buff += "User-Agent: VLC media player (LIVE555 Streaming Media v2010.02.10)"
    buff += END
    buff += "\n"
    go(buff)
# PLAY rtsp://server.com:554/xp RTSP/1.0
# CSeq: 5
# Session: e539b3f49ccf77ea
# Range: AAAAAAAAAAAAAAAAAAAAAAA=0.000-
# User-Agent: VLC media player (LIVE555 Streaming Media v2010.02.10)


def craft14(focus, size):
    print "[*]  -> Fuzzing ", focus, "Fuzzing size set to ", size, " (Advanced crafting 8)"
    buff = ''
    buff += focus
    buff += ' '
    buff += 'rtsp://'
    buff += RHOST
    buff += '/'
    buff += SERVERPATH
    buff += ' RTSP/1.0'
    buff += END
    buff += 'CSeq: 7'
    buff += END
    buff += 'Session: '
    buff += SESSION
    buff += END
    buff += 'Range: '
    if msfpat == "ON":
        buff += createpattern(size)
    else:
        buff += junk*int(size)
    buff += '=0.000-'
    buff += END
    buff += "User-Agent: VLC media player (LIVE555 Streaming Media v2010.02.10)"
    buff += END
    buff += "\n"
    go(buff)
# Clear the previous Log file


def clearlog():
    cl = open('LOG.TXT', 'w')
    cl.write("")
    cl.close()
# Append the buffer size in LOG.TXT


def bufflen(bl):
    bl = str(bl)
    f = open('LOG.TXT', 'w')
    f.write("[*]  Buffer Length :")
    f.write(bl)
    f.write("\nRequest :\n")
    f.close()

# Start Basic Crafting


def start():
    PARAMETERS = ['OPTIONS',
                  'DESCRIBE',
                  'SETUP',
                  'PLAY',
                  'GET_PARAMETER',
                  'TEARDOWN',
                  'PAUSE']
    t = len(PARAMETERS)
    for i in range(0, t):
        line = PARAMETERS[i]
        STS = STARTSIZE
        EDS = ENDSIZE
        STEP = STEPSIZE
        div = EDS/STEP
        line = line.replace("\n", "")
        for i in range(0, div):
            bufflen(STS)
            # print("[*] Start ")
            craft0(line, STS)
            craft1(line, STS)
            craft2(line, STS)
            craft3(line, STS)
            craft4(line, STS)
            time.sleep(DELAY)
            STS = STS+STEP
# Start Advanced Crafting


def startadvcraft():
    STS = STARTSIZE
    EDS = ENDSIZE
    STEP = STEPSIZE
    div = EDS/STEP
    for j in range(0, div):
        STEP = STEPSIZE
        bufflen(STS)
        craft5("DESCRIBE", STS)
        STS = STS+STEP
    STS = STARTSIZE
    STEP = STEPSIZE
    for k in range(0, div):
        bufflen(STS)
        craft6("SETUP", STS)
        craft7("SETUP", STS)
        craft8("SETUP", STS)
        craft9("SETUP", STS)
        craft10("SETUP", STS)
        STS = STS+STEP
    STS = STARTSIZE
    STEP = STEPSIZE
    for l in range(0, div):
        STEP = STEPSIZE
        bufflen(STS)
        craft11("GET_PARAMETER", STS)
        STS = STS+STEP
    STS = STARTSIZE
    STEP = STEPSIZE
    for m in range(0, div):
        STEP = STEPSIZE
        bufflen(STS)
        craft12("TEARDOWN", STS)
        STS = STS+STEP
    STS = STARTSIZE
    STEP = STEPSIZE
    for n in range(0, div):
        STEP = STEPSIZE
        bufflen(STS)
        craft13("PLAY", STS)
        STS = STS+STEP
    STS = STARTSIZE
    STEP = STEPSIZE
    for o in range(0, div):
        STEP = STEPSIZE
        bufflen(STS)
        craft14("PLAY", STS)
        STS = STS+STEP


def createpattern(length):
    length = int(length)
    data = ''.join(tuple(islice(chain.from_iterable(product(
        string.ascii_uppercase, string.ascii_lowercase, string.digits)), length)))
    return data

def start_fuzz():
    STS = STARTSIZE
    EDS = ENDSIZE
    STEP = STEPSIZE
    div = EDS/STEP

    STS = STARTSIZE
    STEP = STEPSIZE
    for n in range(0, div):
        STEP = STEPSIZE
        bufflen(STS)
        # craft6("SETUP",STS)
        method_setup("SETUP", STS)
        STS = STS+STEP

def method_options():
    buff = ''
    buff += 'OPTIONS '  # OPTIONS AAAAAAAAAAAAAAAAA\r\n
    buff += 'rtsp://'
    buff += RHOST
    buff += '/'
    buff += SERVERPATH
    buff += ' RTSP/1.0'
    buff += END
    buff += 'CSeq: 6'
    buff += END
    buff += 'Authorization: Digest username="admin", realm="RTSP", nonce="0000040dY892418598785d2a2304a74adf22f6098f2792", uri="rtsp://192.168.1.56:554/stream0", response="68ddacc4e5411fc6277d2995c9b73fbe"\r\n'
    buff += "User-Agent: LibVLC/3.0.4 (LIVE555 Streaming Media v2016.11.28)\r\n"
    buff += END
    go(buff)

def method_setup(focus,size):
    print "[*]  -> Fuzzing ", focus, "Fuzzing size set to ", size, " (fuzzing SETUP METHOD)"
    # buff = ''
    # buff += focus
    # buff += ' '
    # buff += 'rtsp://'
    # buff += RHOST
    # buff += '/'
    # buff += SERVERPATH
    # buff += ' RTSP/1.0'
    # buff += END
    # buff += 'CSeq: 3'
    # buff += END
    # buff += 'Transport: '
    # if msfpat == "ON":
    #     buff += createpattern(size)
    # else:
    #     buff += junk*int(size)
    # buff += '/'
    # buff += 'AVP;unicast;client_port=36142-36143'
    # buff += END
    # buff += "User-Agent: VLC media player (LIVE555 Streaming Media v2010.02.10)"
    # buff += END
    # buff += "\n"
    # go(buff)

    # focus = 'SETUP'
    # key = computeKey()
    buff = ''
    buff += focus
    buff += ' '
    buff += 'rtsp://'
    buff += RHOST
    buff += '/'
    buff += SERVERPATH
    buff += ' RTSP/1.0'
    buff += END
    buff += 'CSeq: 7'
    buff += END
    buff += 'Authorization: Digest username="admin", realm="RTSP", nonce="0000040dY892418598785d2a2304a74adf22f6098f2792", uri="rtsp://192.168.1.56:554/stream0", response="c00ad57f9dcc4485f404d31b844665c2"\r\n'
    # buff += "User-Agent: LibVLC/3.0.4 (LIVE555 Streaming Media v2016.11.28)"
    # buff += "User-Agent: "
    # buff += END
    buff += 'Transport: RTP/AVP;unicast;client_port=49702-49703'
    # buff += 'Session: '
    # buff += SESSION
    # buff += END
    # buff += "Range: npt=0.000-\r\n"
    buff += END
    buff += END

    # buff += 'Range: '
    # if msfpat == "ON":
    #     buff += createpattern(size)
    # else:
    #     buff += junk*int(size)
    # buff += '=0.000-'
    # buff += END
    # buff += "\n"
    # raw_input('sss')
    go(buff)
def computeKey():
    username = 'admin'
    realm = 'RTSP'
    password = 'pass'
    nonce = '0000040dY892418598785d2a2304a74adf22f6098f2792'
    method = 'SETUP'
    url = 'rtsp://192.168.1.56:554/stream0/'

    m1 = hashlib.md5(username + ":" + realm + ":" + password).hexdigest()
    m2 = hashlib.md5(method + ":" + url).hexdigest()
    response = hashlib.md5(m1 + ":" + nonce + ":" + m2).hexdigest()
    raw_input(response)
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

# Little Bit Typecasting
RPORT = int(RPORT)
STARTSIZE = int(STARTSIZE)
ENDSIZE = int(ENDSIZE)
STEPSIZE = int(STEPSIZE)
STOPAFTER = int(STOPAFTER)
DELAY = int(DELAY)
# raw_input(STOPAFTER)
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
raw_input("[*] If above information are correct Press Enter \nto start fuzzing if not then re-edit the rtsp.conf file _")
if msfpat == "ON":
    print "[*] You are going to start fuzzing with Metasploit Pattern"
    print "[*] This fuzzing process may take some extra time"
    q = raw_input("[*] Are you sure(y/n)??")
    if q == "n":
        print "[*] Turning off Metasploit Pattern feature.."
        msfpat = "OFF"
clearlog()
start()
print "[*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*]"
print "[*]                  Starting Advanced fuzzing with Specially Crafted requests               [*]"
print "[*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*]"
for i in range(10):
    startadvcraft()
# start_fuzz()
print "[*] To see last successful request go to LOG.TXT file"
print "[*] Exiting."
