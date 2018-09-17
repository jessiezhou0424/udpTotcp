import socket
import sys
import random
import struct
import time
import threading
import os
import collections
import pickle

if sys.platform == 'win32':
    def getTime():
        return  time.clock()
else:
    def getTime():
        return time.time()
assert(time is not None)

def send_Thread():
    global GLOBAL_STATE,timer,timeout,base,nextseq,s,startTime
    while GLOBAL_STATE==1:
        while nextseq<=bufferLength:
            if (nextseq+MSS<=bufferLength):
                dataToSend=buffer[nextseq:nextseq+MSS]
                segment=struct.pack('iii'+str(MSS)+'s',nextseq+seq,SEQreceived+1,flagFIN,dataToSend)
            else:
                if bufferLength==0:
                    dataToSend=b''
                    print(len(dataToSend))
                    segment=struct.pack('iii0s',nextseq+seq,SEQreceived+1,flagFIN,dataToSend)
                else:
                    dataToSend=buffer[nextseq:]
                    segment=struct.pack('iii'+str(len(dataToSend))+'s',nextseq+seq,SEQreceived+1,flagFIN,dataToSend)
            if (nextseq<base+windowN):
                dropedPkt[nextseq+seq]=segment
                #pkt drop
                if (random.random()<=pdrop):
                    global dropedNum
                    dropedNum+=1
                    logFile.write("drop "+'{:>9.2f}'.format(getTime()*1000)+"     D     "+'{:>6d}'.format(nextseq+seq)+'    '+'{:>6d}'.format(len(dataToSend))+'    '+str(SEQreceived+1)+'\n')
                    #Why thread does not start
                    if(base==nextseq):
                        startTimer=threading.Thread(target=timer.start_timer)
                        startTime=getTime()
                        startTimer.start()
                    nextseq+=MSS
                else:
                    #pkt sent
                    logFile.write("snd  "+'{:>9.2f}'.format(getTime()*1000)+"     D     "+'{:>6d}'.format(nextseq+seq)+'    '+'{:>6d}'.format(len(dataToSend))+'    '+str(SEQreceived+1)+'\n')
                    global  segmentNum
                    segmentNum+=1
                    if(base==nextseq):
                        startTimer=threading.Thread(target=timer.start_timer)
                        startTime=getTime()
                        startTimer.start()
                    nextseq+=MSS
                    s.sendto(segment, (receiver_host_ip, receiver_port))
                    timeRecording[base+seq].append(getTime())



def resend():
    global pdrop,rcvACKs,timer,dropedPkt,base,seq,GLOBAL_STATE,startTime
    if (random.random()<=pdrop):
        global dropedNum
        dropedNum+=1
        if (len(rcvACKs)==0):
            logFile.write("drop "+'{:>9.2f}'.format(getTime()*1000)+"     D     "+'{:>6d}'.format(base+seq)+'    '+'{:>6d}'.format(len(dropedPkt[base+seq])-12)+'    '+str(SEQreceived+1)+'\n')
        else:
            if rcvACKs[-1] in dropedPkt.keys():
                logFile.write("drop "+'{:>9.2f}'.format(getTime()*1000)+"     D     "+'{:>6d}'.format(rcvACKs[-1])+'    '+'{:>6d}'.format(len(dropedPkt[rcvACKs[-1]])-12)+'    '+str(SEQreceived+1)+'\n')
    else:
        #pkt sent
        global segmentRetrans
        segmentRetrans+=1
        if (len(rcvACKs)==0):
            logFile.write("snd  "+'{:>9.2f}'.format(getTime()*1000)+"     D     "+'{:>6d}'.format(base+seq)+'    '+'{:>6d}'.format(len(dropedPkt[base+seq])-12)+'    '+str(SEQreceived+1)+'\n')
            s.sendto(dropedPkt[base+seq], (receiver_host_ip, receiver_port))
            timeRecording[base+seq].append(getTime())
        else:
            if rcvACKs[-1] in dropedPkt.keys():
                logFile.write("snd  "+'{:>9.2f}'.format(getTime()*1000)+"     D     "+'{:>6d}'.format(rcvACKs[-1])+'    '+'{:>6d}'.format(len(dropedPkt[rcvACKs[-1]])-12)+'    '+str(SEQreceived+1)+'\n')
                s.sendto(dropedPkt[rcvACKs[-1]], (receiver_host_ip, receiver_port))
                timeRecording[rcvACKs[-1]].append(getTime())

class myTimer(object):
    def __init__(self, timeout):
        self.start =getTime()
        self.timeout = timeout/1000
        self.is_running = False
        self.is_timeout=False

    def TimerTimeout(self):
        global startTime,GLOBAL_STATE
        if GLOBAL_STATE==2:
            return False
        if self.is_running==False:
            return False
        if getTime() - startTime >= self.timeout:
            self.is_timeout=True
            resend()
            startTimer=threading.Thread(target=timer.start_timer)
            startTime=getTime()
            startTimer.start()
            return True
        else:
            return False

    def start_timer(self):
        global GLOBAL_STATE
        if GLOBAL_STATE==1:
            self.is_running = True
            self.start = getTime()
            time.sleep(self.timeout)
            self.TimerTimeout()

    def stop_timer(self):
        self.is_running = False


def receive_thread():
    global rcvACKs,timer,startTime,seq
    global base
    global GLOBAL_STATE,s
    while GLOBAL_STATE == 1:
        ACKreceived=int(bytes.decode(s.recvfrom(20)[0]))
        timeRecording[ACKreceived-MSS].append(getTime())
        if ACKreceived>bufferLength:
            GLOBAL_STATE=2
        base=ACKreceived-seq#base start from 0
        if ACKreceived in rcvACKs:
            global duplicateACKs
            duplicateACKs+=1
        rcvACKs.append(ACKreceived)
        logFile.write("rcv  "+'{:>9.2f}'.format(getTime()*1000)+"     A     "+'{:>6d}'.format(SEQreceived+1)+'    '+'{:>6d}'.format(0)+'    '+str(ACKreceived)+'\n')
        #Why thread does not start
        if (base!=nextseq):
            startTimer=threading.Thread(target=timer.start_timer)
            startTime=getTime()
            startTimer.start()
        if (len(rcvACKs)>=4):
            #快速重传
            if (rcvACKs[-1]==rcvACKs[-2] and rcvACKs[-2]==rcvACKs[-3] and rcvACKs[-4]==rcvACKs[-3]):
                rcvACKs.pop()
                rcvACKs.pop()
                rcvACKs.pop()
                resend()


dataAmount=0
segmentNum=0
dropedNum=0
delayedNum=0
segmentRetrans=0
duplicateACKs=0
timeRecording=collections.defaultdict(list)
if(os.path.isfile('Sender_log.txt')):
    os.remove('Sender_log.txt')
logFile=open ('Sender_log.txt','a')
#establish connection
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
GLOBAL_STATE = 0 # 0 : three-way handshaking 1 : transmitting 2: four segments terminating
argvList=sys.argv
receiver_host_ip,receiver_port=argvList[1],int(argvList[2])
fileName,MWS,MSS,timeout=argvList[3],int(argvList[4]),int(argvList[5]),int(argvList[6])
#fileName,MWS,MSS,gamma=argvList[3],int(argvList[4]),int(argvList[5]),int(argvList[6])
#pdrop,seed=float(argvList[7]),int(argvList[10])
#pdelay,MaxDelay=float(argvList[8]),int(argvList[9])
pdrop,seed=float(argvList[7]),int(argvList[8])
random.seed(seed)
flagSYN=1
flagFIN=0
seq=0#random.randint(0,100)
#header flagSTN,flagFIN,seq,ack
#send syn
SYNsend=struct.pack('iii',flagSYN,flagFIN,seq)
logFile.write("snd  "+'{:>9.2f}'.format(getTime()*1000)+"     S     "+'{:>6d}'.format(seq)+'    '+'{:>6d}'.format(0)+'   0'+'\n')
seq+=1
s.sendto(SYNsend,(receiver_host_ip, receiver_port))
#recieve syn and ack=seq+1
data,addr=s.recvfrom(20)
SYNreceived,FINreceived,ACKreceived,SEQreceived=struct.unpack('iiii',data)
logFile.write("rcv  "+'{:>9.2f}'.format(getTime()*1000)+"     SA    "+'{:>6d}'.format(SEQreceived)+'    '+'{:>6d}'.format(0)+'    '+str(ACKreceived)+'\n')
GLOBAL_STATE = 1
dropedPkt={}
if (ACKreceived==seq):
    #connection established, send ack to receiver, then send data
    ACKsend=struct.pack('ii',seq,(SEQreceived+1))
    logFile.write("snd  "+'{:>9.2f}'.format(getTime()*1000)+"     A     "+'{:>6d}'.format(seq)+'    '+'{:>6d}'.format(0)+'    '+str(SEQreceived+1)+'\n')
    s.sendto(ACKsend,(receiver_host_ip, receiver_port))
    with open ('./'+argvList[3],"rb") as file:
        buffer= file.read()
    bufferLength=len(buffer)
    print(bufferLength)
    base=0
    windowN=MWS
    nextseq=base
    rcvACKs = []
    handleRcver = threading.Thread(target=receive_thread)
    handleSender = threading.Thread(target=send_Thread)
    startTime=getTime()
    timer=myTimer(timeout)
    handleSender.start()
    handleRcver.start()
while GLOBAL_STATE==1:
    continue
if GLOBAL_STATE==2:
    while handleRcver.is_alive() or handleSender.is_alive():
        time.sleep(0.001)
    #close connection
    #send FIN
    flagFIN=1
    seq=seq+bufferLength
    FINsend=struct.pack('ii',seq,flagFIN)
    s.sendto(FINsend,(receiver_host_ip, receiver_port))
    logFile.write("snd  "+'{:>9.2f}'.format(getTime()*1000)+"     F     "+'{:>6d}'.format(seq)+'    '+'{:>6d}'.format(0)+'    '+str(SEQreceived+1)+'\n')
    seq+=1
    #receive ACK and FIN
    data2=int(bytes.decode(s.recvfrom(20)[0]))
    #segment=struct.pack('i',ACKsend)
    logFile.write("rcv  "+'{:>9.2f}'.format(getTime()*1000)+"     FA    "+'{:>6d}'.format(SEQreceived+1)+'    '+'{:>6d}'.format(0)+'    '+str(seq)+'\n')
    #send ACK
    segment=struct.pack('ii',seq,SEQreceived+2)
    s.sendto(segment,(receiver_host_ip, receiver_port))
    logFile.write("snd  "+'{:>9.2f}'.format(getTime()*1000)+"     A     "+'{:>6d}'.format(seq)+'    '+'{:>6d}'.format(0)+'    '+str(SEQreceived+2)+'\n')
    time.sleep(1)
    s.close()
    dataAmount=bufferLength
    logFile.write("Amount of Data Transferred: "+str(dataAmount)+'\n')
    logFile.write("Number of Data Segments Sent: "+str(segmentNum)+'\n')
    logFile.write("Number of packets Dropped: "+str(dropedNum)+'\n')
    logFile.write("Number of Retransmitted Segments: "+str(segmentRetrans)+'\n')
    logFile.write("Number of Duplicate Acknowlwdgements received: "+str(duplicateACKs)+'\n')
    logFile.close()



