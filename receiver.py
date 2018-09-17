import socket
import sys
import os
import struct
import time
import pickle
#build connection
#flag 要在每个packet里！
if sys.platform == 'win32':
    def getTime():
        return  time.clock()
else:
    def getTime():
        return time.time()
assert(time is not None)

receivedAmount=0
receivedSegment=0
duplicateSegment=0

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
argvList=sys.argv
flagSYN=1
flagFIN=0
receiver_port=int(argvList[1])
fileName=argvList[2]
seq=0#random.randint(101,200)
s.bind(("localhost",receiver_port))
GLOBAL_STATE = 0 # 0 : three-way handshaking 1 : transmitting 2: four segments terminating
#receive syn from sender
data, addr = s.recvfrom(1024)
#senderSide:SYNsend=struct.pack('iii',flagSYN,flagFIN,seq)
data=struct.unpack('iii',data)
ack=data[2]+1
SenderFileSeq=ack
if(os.path.isfile('Receiver_log.txt')):
    os.remove('Receiver_log.txt')
logFile=open ('Receiver_log.txt','a')
logFile.write("rcv  "+'{:>9.2f}'.format(getTime()*1000)+"     S     "+'{:>6d}'.format(data[2])+'    '+'{:>6d}'.format(0)+'    '+str(0)+'\n')
#send syn and ack back
SYNACK=struct.pack('iiii',flagSYN,flagFIN,ack,seq)
print(seq)
s.sendto(SYNACK, addr)
logFile.write("snd  "+'{:>9.2f}'.format(getTime()*1000)+"     SA    "+'{:>6d}'.format(seq)+'    '+'{:>6d}'.format(0)+'    '+str(ack)+'\n')
#receive ack from sender
data, addr = s.recvfrom(50)
data=struct.unpack('ii',data)
ACKreceived=data[1]
logFile.write("rcv  "+'{:>9.2f}'.format(getTime()*1000)+"     A     "+'{:>6d}'.format(data[0])+'    '+'{:>6d}'.format(0)+'    '+str(ACKreceived)+'\n')
#if received ack=seq+1 then connection established
SeqList=[]
rcvdict={}
if (ACKreceived==seq+1):
    if(os.path.isfile(fileName)):
        os.remove(fileName)
    GLOBAL_STATE = 1 # 0 : three-way handshaking 1 : transmitting 2: four segments terminating
    while GLOBAL_STATE==1:
        data, addr = s.recvfrom(1024)
        MSS=len(data)-12
        if MSS>0:
            data=struct.unpack('iii'+str(MSS)+'s',data)
            logFile.write("rcv  "+'{:>9.2f}'.format(getTime()*1000)+"     D     "+'{:>6d}'.format(data[0])+'    '+'{:>6d}'.format(MSS)+'    '+str(ACKreceived)+'\n')
            if data[0] in rcvdict.keys():
                duplicateSegment+=1
            if (data[0]==int(SenderFileSeq)):
                rcvdict[data[0]]=data[3]
                #segment=struct.pack('iii'+str(len(dataToSend))+'s',nextseq+seq,SEQreceived+1,flagFIN,dataToSend)
                keycheck=data[0]+MSS
                while keycheck in rcvdict.keys():
                    keycheck+=MSS
                ACKsend =str(keycheck)
                SenderFileSeq=ACKsend
                SeqList.append(ACKsend)
                s.sendto(ACKsend.encode('utf-8'), addr)
                logFile.write("sdn  "+'{:>9.2f}'.format(getTime()*1000)+"     A     "+'{:>6d}'.format(ACKreceived)+'    '+'{:>6d}'.format(0)+'    '+str(ACKsend)+'\n')
            else:
                rcvdict[data[0]]=data[3]
                s.sendto(SeqList[-1].encode('utf-8'), addr)
                logFile.write("sdn  "+'{:>9.2f}'.format(getTime()*1000)+"     A     "+'{:>6d}'.format(ACKreceived)+'    '+'{:>6d}'.format(0)+'    '+str(SeqList[-1])+'\n')

        else:
            if MSS==0:
                rcvdict[data[0]]=b''
                data2=struct.unpack('iii',data)
                logFile.write("rcv  "+'{:>9.2f}'.format(getTime()*1000)+"     D     "+'{:>6d}'.format(data[0])+'    '+'{:>6d}'.format(MSS)+'    '+str(ACKreceived)+'\n')
                s.sendto(str(data2[0]).encode('utf-8'), addr)
                logFile.write("sdn  "+'{:>9.2f}'.format(getTime()*1000)+"     A     "+'{:>6d}'.format(ACKreceived)+'    '+'{:>6d}'.format(0)+'    '+str(data2[0])+'\n')
                data, addr = s.recvfrom(1024)
            GLOBAL_STATE=2
    #receive and unpack seq and FIN
    #FINsend=struct.pack('ii',seq,flagFIN)
    if GLOBAL_STATE==2:
        data=struct.unpack('ii',data)
        logFile.write("rcv  "+'{:>9.2f}'.format(getTime()*1000)+"     F     "+'{:>6d}'.format(data[0])+'    '+'{:>6d}'.format(0)+'    '+str(seq+1)+'\n')
        #send FIN and ACK back
        flagFIN=1
        seq+=1
        ACKsend2=str(data[0]+1)
        print (ACKsend2)
        logFile.write("snd  "+'{:>9.2f}'.format(getTime()*1000)+"     FA    "+'{:>6d}'.format(seq)+'    '+'{:>6d}'.format(0)+'    '+str(ACKsend2)+'\n')
        s.sendto(ACKsend2.encode('utf-8'), addr)
        #receive ACK
        data,addr=s.recvfrom(20)
        data=struct.unpack('ii',data)
        logFile.write("rcv  "+'{:>9.2f}'.format(getTime()*1000)+"     A     "+'{:>6d}'.format(data[0])+'    '+'{:>6d}'.format(0)+'    '+str(data[1])+'\n')
        if data[1]==seq+1:
            s.close()
        else:
            s.sendto(ACKsend2.encode('utf-8'),addr)

keyList=sorted(rcvdict.keys())
with open(fileName,'wb') as file:
    file.write(rcvdict[keyList[0]])
    receivedAmount+=len(rcvdict[keyList[0]])
if len(keyList)>1:
    for i in keyList[1:]:
        with open(fileName,'ab') as file:
            file.write(rcvdict[i])
            receivedAmount+=len(rcvdict[i])
logFile.write('Amount of Data Received: '+str(receivedAmount)+'\n')
logFile.write('Amount of Data Segment Received: '+str(len(rcvdict))+'\n')
logFile.write('Amount of Duplicate Segment Received: '+str(duplicateSegment)+'\n')
logFile.close()