connection_manager
==================

openfire connection manager module

![connection manager architecture](docs/architecture.png "Architecture")

Openfire Connection Manager 是 Openfire 服务器的扩展，它可以透明的处理大规模并发 XMPP 客户端对 Openfire 服务器的联接。上图表示 Openfire 服务器配置 Connection Manager 后的系统架构。实现参考了Openfire的Connection Manager模块.

使用配置
-------------------

		tcp {
			upstream cluster {
				# simple round-robin
				server 127.0.0.1:5262 ;		#openfire server
				server 10.211.55.3:5262;	#openfire server
				connections 5;				#cm与openfire server的最大连接数
				keepalive_timeout 65;		#cm与openfire server keepalive
				server_name test;			#cm名称
				check interval=10000 rise=2 fall=5 timeout=30000;	#check openfire server配置
			}
		
			server {
				listen 15222;				#cm监听端口
				xmpp_read_timeout 6000;		#client与cm的read_timeout
				xmpp_send_timeout 6000;		#cm到client的send_timeout
				xmpp_buffer 4096;			#client <=> cm 及 cm <=> openfire数据交换buffer
				xmpp_pass cluster;			#cm转发的路径配置
			}
		}

		
原理篇
-------------------
### Connection Manager的总体结构<br />
