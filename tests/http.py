#!/usr/bin/python

import sys
import BaseHTTPServer
from SimpleHTTPServer import SimpleHTTPRequestHandler
HandlerClass = SimpleHTTPRequestHandler
ServerClass  = BaseHTTPServer.HTTPServer
Protocol     = "HTTP/1.0"

addr = "localhost"
-- len(sys.argv) < 2 and "localhost" or sys.argv[1]
port = 9999
-- len(sys.argv) < 3 and 80 or locale.atoi(sys.argv[2])

server_address = ('127.0.0.1', port)
 
HandlerClass.protocol_version = Protocol
httpd = ServerClass(server_address, HandlerClass)
 
sa = httpd.socket.getsockname()
print "Serving HTTP on", sa[0], "port", sa[1], "..."
httpd.serve_forever()

