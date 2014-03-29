#!/usr/bin/python

from SocketServer import TCPServer, BaseRequestHandler #StreamRequestHandler
import traceback
import time
import xml.parsers.expat

level = 0
global sock_obj
xmpp_obj = {}


def start_element(name, attrs):
	global level
	global sock_obj
	global xmpp_obj
	print '\t'*level, level, name, attrs
	if (level == 0) :
		if(name == "stream:stream"):
			sock_obj.sendall("<stream:stream id=\"d5606bc5\" to=\"10.19.220.237\" xmlns=\"jabber:client\" xmlns:stream=\"http://etherx.jabber.org/streams\" version=\"1.0\"><stream:features xmlns:stream=\"http://etherx.jabber.org/streams\"><compression xmlns=\"http://jabber.org/features/compress\"><method>zlib</method></compression></stream:features>")
	elif (level == 1):
		if(name == "route"):
			xmpp_obj["chnid"] = attrs["id"]
		elif(name == "iq"):
			xmpp_obj["type"] = attrs["type"]
			xmpp_obj["chnid"] = attrs["id"]
	
	level = level + 1


def end_element(name):
	global level
	global sock_obj
	global xmpp_obj
	level = level - 1
	print '\t'*level, '</', name,">"
	if(level == 1):
		if(name == "handshake"):
			sock_obj.sendall("<handshake/>")
			sock_obj.sendall("<iq type=\"set\" id=\"541-1299\"><configuration xmlns=\"http://jabber.org/protocol/connectionmanager\"><mechanisms xmlns=\"urn:ietf:params:xml:ns:xmpp-sasl\"><mechanism>AASAUTH</mechanism></mechanisms><compression xmlns=\"http://jabber.org/features/compress\"><method>zlib</method></compression><auth xmlns=\"http://jabber.org/features/iq-auth\" /><register xmlns=\"http://jabber.org/features/iq-register\" /></configuration></iq>")
		elif(name == "iq"):
			#if(xmpp_obj["type"] == "set"):
			sock_obj.sendall("<iq type=\"result\" id=\""+xmpp_obj["chnid"]+"\" from=\"etop.com\" to=\"4ltv4/ConnectionManager-0-Connection Worker - 1\"><session xmlns=\"http://jabber.org/protocol/connectionmanager\" id=\""+xmpp_obj["chnid"]+"\"><create><host name=\"CNHQ-13060506T.sn.suning.ad\" address=\"10.23.22.188\" /></create></session></iq>")
			#elif(xmpp_obj["type"] == "set"):
			#	sock_obj.sendall("<iq type=\"result\" id=\"523-0\" from=\"etop.com\" to=\"4ltv4/ConnectionManager-0-Connection Worker - 1\"><session xmlns=\"http://jabber.org/protocol/connectionmanager\" id=\"4ltv4267a97f\"><create><host name=\"CNHQ-13060506T.sn.suning.ad\" address=\"10.23.22.188\" /></create></session></iq>")
		elif(name == "route"):
			str = "<route id=\""+xmpp_obj["chnid"]+"\"><messages a=\"0\">hello world!</messages></route>"
			sock_obj.sendall(str)
		else:
			sock_obj.sendall("<stream:error xmlns:stream=\"http://etherx.jabber.org/streams\"><not-authorized xmlns=\"urn:ietf:params:xml:ns:xmpp-streams\" /></stream:error>")
	

class MyStreamRequestHandlerr(BaseRequestHandler):#StreamRequestHandler):
	def handle(self):
		print '*'*50
		print "* receive from " , self.client_address
		global sock_obj
		global xmpp_obj
		sock_obj = self.request #self.wfile
		p = 0
		p = xml.parsers.expat.ParserCreate()
		p.StartElementHandler = start_element
		p.EndElementHandler = end_element
		#p.CharacterDataHandler = char_data
		p.returns_unicode = False
		tmp = {}
		while True:
			try:
				#data = self.rfile.read(102)
				data = self.request.recv(1024) 
				tmp = data
				print '#'*2, data
				if not data: 
					time.sleep(1)
					#continue 
					break
				#data = self.rfile.readline().strip()
				if("</stream:stream>" == data):
					self.request.sendall("</stream:stream>")
					break
				p.Parse(data)
				#self.wfile.write(data.upper())
				#
			except:
				traceback.print_exc()
				print tmp
				break
		#p.close()
		p = 0
		print '*'*50


if __name__ == "__main__":
	host = ""
	port = 4444 
	addr = (host, port)
	server = TCPServer(addr, MyStreamRequestHandlerr)
	server.serve_forever()
	server.close()

