#!/usr/bin/python

import socket,threading

HOST = '127.0.0.1'
HOST = '10.19.220.237'
#HOST = '10.19.220.188'
#HOST = '10.19.220.193'
#HOST ='192.168.148.211'
#HOST ='192.168.148.212'
#HOST ='192.168.148.213'
#HOST ='192.168.148.214'

PORT = 3333 
PORT = 5222


import xml.parsers.expat

level = 0
global sock_obj
global xmpp_obj


def start_element(name, attrs):
	global level
	global sock_obj
	global xmpp_obj
	print '\t'*level, 'Start element:', name, attrs
	if (level == 0) :
		if(name == "stream:stream"):
			sock_obj.write("<stream:stream to=\"10.19.220.237\" xmlns=\"jabber:client\" xmlns:stream=\"http://etherx.jabber.org/streams\" version=\"1.0\">")
			sock_obj.write("<stream:features xmlns:stream=\"http://etherx.jabber.org/streams\"><compression xmlns=\"http://jabber.org/features/compress\"><method>zlib</method></compression></stream:features>")
	elif (level == 1):
		if(name == "route"):
			xmpp_obj["chnid"] = attrs["id"]
	
	level = level + 1


def end_element(name):
	global level
	global sock_obj
	global xmpp_obj
	level = level - 1
	if(level == 1):
		if(name == "handshake"):
			sock_obj.write("<handshake/>")
			sock_obj.write("<iq type=\"set\" id=\"541-1299\"><configuration xmlns=\"http://jabber.org/protocol/connectionmanager\"><mechanisms xmlns=\"urn:ietf:params:xml:ns:xmpp-sasl\"><mechanism>AASAUTH</mechanism></mechanisms><compression xmlns=\"http://jabber.org/features/compress\"><method>zlib</method></compression><auth xmlns=\"http://jabber.org/features/iq-auth\" /><register xmlns=\"http://jabber.org/features/iq-register\" /></configuration></iq>")
		elif(name == "iq"):
			sock_obj.write("<iq type=\"result\" id=\"523-0\" from=\"etop.com\" to=\"4ltv4/ConnectionManager-0-Connection Worker - 1\"><session xmlns=\"http://jabber.org/protocol/connectionmanager\" id=\"4ltv4267a97f\"><create><host name=\"CNHQ-13060506T.sn.suning.ad\" address=\"10.23.22.188\" /></create></session></iq>")
		elif(name == "route"):
			sock_obj.write("<route id=\""+xmpp_obj["chnid"]+"\"><messages a=0>hello world!</messages></route>")
			print '\t'*level, 'End element:', name
		elif(name == "stream:stream"):
			s.close()
		else:
			sock_obj.write("<stream:error xmlns:stream=\"http://etherx.jabber.org/streams\"><not-authorized xmlns=\"urn:ietf:params:xml:ns:xmpp-streams\" /></stream:error>")
			print '\t'*level, 'End element:', name


msg_seq=[
         #{"msg":"<route id='123'><xml version='1.0' encoding='UTF-8'/></route>","ack":0},
         {"msg":"<stream:stream to=\"10.19.220.237\" xmlns=\"jabber:client\" xmlns:stream=\"http://etherx.jabber.org/streams\" version=\"1.0\">","ack":1},
	{"msg":"<handshake>4030e7b717bcde31399cdf3da14ecaa3977aced8</handshake>","ack":1},
	{"msg":"<iq type=\"set\" id=\"541-1299\"><configuration xmlns=\"http://jabber.org/protocol/connectionmanager\"><mechanisms xmlns=\"urn:ietf:params:xml:ns:xmpp-sasl\"><mechanism>AASAUTH</mechanism></mechanisms><compression xmlns=\"http://jabber.org/features/compress\"><method>zlib</method></compression><auth xmlns=\"http://jabber.org/features/iq-auth\" /><register xmlns=\"http://jabber.org/features/iq-register\" /></configuration></iq>","ack":1},
	{"msg":"<iq type='set' to='etop.com' from='4ltv4/ConnectionManager' id='523-0'><session xmlns='http://jabber.org/protocol/connectionmanager' id='%s'><create><host name='CNHQ-13060506T.sn.suning.ad' address='10.23.22.188' /></create></session></iq>","ack":1},
	
         {"msg":"<route id='123'><auth mechanism=\"AASAUTH\" xmlns=\"urn:ietf:params:xml:ns:xmpp-sasl\">NmE5NGIwZTlkZTZmYmJkZTVhYjY3ODhjYjViMzg1Y2IyMDBmMWE1OWE5YWZlZTk2NWYwODhkMTRhYzkzYTcyNA==</auth></route>","ack":1},
         {"msg":"<route id='123'><presence id=\"J00Fa-34\" to=\"111223@conference.etop.com/6001738977\"><x xmlns=\"http://jabber.org/protocol/muc\"/></presence></route>","ack":1},
         {"msg":"<route id='123'><message id=\"5YUme-47\" from=\"111223@conference.etop.com/6001738977\"  to=\"111223@conference.etop.com\"><x xmlns=\"http://jabber.org/protocol/muc#user\"><invite to=\"6000059759@etop.com\"><reason>missing</reason></invite><invite to=\"6000608066@etop.com\"><reason>please add...</reason></invite><invite to=\"6000059859@etop.com\"><reason>meeting...</reason></invite></x></message></route>","ack":0},
         {"msg":"<route id='123'><iq id=\"5krX2-21\" to=\"conference.etop.com\" type=\"get\"><query xmlns=\"jabber:iq:load:rooms\" /></iq></route>","ack":1},
	{"msg":"</stream:stream>","ack":1}
    ]

# The same port as used by the server
def send_hand(index,s):
	global sock_obj
	sock_obj = s
	p = xml.parsers.expat.ParserCreate()
	p.StartElementHandler = start_element
	p.EndElementHandler = end_element
	#p.CharacterDataHandler = char_data
	p.returns_unicode = False
	
	for msg in msg_seq:
		print 'Send:\t', msg["msg"]
		s.send(msg["msg"])
		if(msg["ack"]==1):
			print 'Received:\t'
			#while True:
			data = s.recv(1024)
			if not data: break
			else:
				print "\t",repr(data)
	s.close()

for i in range(1):
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((HOST, PORT))
	th = threading.Thread(target=send_hand,args=(i,s) )
	th.start()
	th.join()

