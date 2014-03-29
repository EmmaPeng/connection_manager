#!/usr/bin/python

import socket,threading

HOST = '127.0.0.1'
HOST = '10.19.220.237'
#HOST = '10.22.3.157'
#HOST = '10.23.22.87'

PORT = 3333 
PORT = 5222
#curl http://10.19.220.231:8088/aas/user/login.do -d "userId=13000001@qq.com&password=xuan01" -v  13000001@qq.com xuan01
msg_seq=[
         {"msg":"<?xml version='1.0' encoding='UTF-8'?>","ack":0},
         {"msg":"<stream:stream to=\"10.19.220.237\" xmlns=\"jabber:client\" xmlns:stream=\"http://etherx.jabber.org/streams\" version=\"1.0\">","ack":1},
         {"msg":"<auth mechanism=\"AASAUTH\" xmlns=\"urn:ietf:params:xml:ns:xmpp-sasl\">YTFlYzdlYjAtNjU0Mi00NDQ3LWJlNWMtMDNlNDcyNWY0NGM0</auth>","ack":1},
         {"msg":"<presence id=\"J00Fa-34\" to=\"111223@conference.etop.com/6001738977\"><x xmlns=\"http://jabber.org/protocol/muc\"/></presence>","ack":1},
         {"msg":"<message id=\"5YUme-47\" from=\"111223@conference.etop.com/6001738977\"  to=\"111223@conference.etop.com\"><x xmlns=\"http://jabber.org/protocol/muc#user\"><invite to=\"6000059759@etop.com\"><reason>missing</reason></invite><invite to=\"6000608066@etop.com\"><reason>please add...</reason></invite><invite to=\"6000059859@etop.com\"><reason>meeting...</reason></invite></x></message>","ack":0},
         {"msg":"<iq id=\"5krX2-21\" to=\"conference.etop.com\" type=\"get\"><query xmlns=\"jabber:iq:load:rooms\" /></iq>","ack":1},
	{"msg":"</stream:stream>","ack":1}
    ]


# The same port as used by the server
def send_hand(index,s):
	for msg in msg_seq:
		print 'Send:\t', msg["msg"]
		s.send(msg["msg"])
		if(msg["ack"]==1):
			data = s.recv(1024)
			print 'Received:\t', repr(data)


for i in range(1):
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((HOST, PORT))
	th = threading.Thread(target=send_hand,args=(i,s) )
	th.start()
	th.join()
	s.close()
