/*
 * =====================================================================================
 *
 *       Filename:  client.c
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  01/20/2014 04:42:15 AM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  Humphery yu (), humphery.yu@gmail.com
 *   Organization:  
 *
 * =====================================================================================
 */

//#include <stdio.h>
//#include <stdlib.h>
//#include <errno.h>
//#include <strings.h>
//#include <sys/types.h>
//#include <sys/socket.h>
//#include <sys/ioctl.h>
//#include <arpa/inet.h>
//#include <unistd.h>
//#include <string.h>

#include <ngx_config.h>
#include <ngx_core.h>
#include <expat.h>
#include <test_socket.h>
#include <packet.h>


#define SER_IP "127.0.0.1"
#define SER_PORT 9999
#define MAX_LINE 4096 

ngx_cycle_t *cycle;
ssize_t packet_head_len=sizeof(packet_head);

//typedef u_char u_char;

static u_char recvStr[MAX_LINE];

ngx_cycle_t *init_nginx();

enum packet_type{iq=1,presence,message};

typedef struct {
	XML_Parser parser;
	int	depth;
	int packet_type;		
}req_ctx_t;

ssize_t send_myself(int fd,u_char *msg)
{
     ssize_t n;
     int size=strlen((char*)msg);

     test_connection_t c;
     c.fd=fd;

     u_char *packet=(u_char*)malloc(packet_head_len+size);
     packet_head *phead = packet;
     phead->chid=fd;
     phead->len=size;
     memcpy(packet+packet_head_len,msg,size);
     n=test_unix_send(&c,packet, size+packet_head_len);
     if(n==NGX_ERROR) return -1;
     printf("Send:	%s\n",msg);

     if(memcmp(msg,"<message ",9)==0 || memcmp(msg,"<?xml ",6)==0)return 0;
     memset(recvStr,0,MAX_LINE);
     n = test_unix_recv(&c,recvStr,MAX_LINE -1);
     if(n == NGX_OK)
	printf("Recv:      %s\n",recvStr);
     return n;
}

static u_char packets[7][40960]={
"<?xml version='1.0' encoding='UTF-8'?>",
"<stream:stream to=\"10.19.220.237\" xmlns=\"jabber:client\" xmlns:stream=\"http://etherx.jabber.org/streams\" version=\"1.0\">"
"<auth mechanism=\"AASAUTH\" xmlns=\"urn:ietf:params:xml:ns:xmpp-sasl\">NmE5NGIwZTlkZTZmYmJkZTVhYjY3ODhjYjViMzg1Y2IyMDBmMWE1OWE5YWZlZTk2NWYwODhkMTRhYzkzYTcyNA==</auth>"
"<presence id=\"J00Fa-34\" to=\"111223@conference.etop.com/6001738977\"><x xmlns=\"http://jabber.org/protocol/muc\"/></presence>",
"<message id=\"5YUme-47\" from=\"111223@conference.etop.com/6001738977\"  to=\"111223@conference.etop.com\"><x xmlns=\"http://jabber.org/protocol/muc#user\"><invite to=\"6000059759@etop.com\"><reason>missing</reason></invite><invite to=\"6000608066@etop.com\"><reason>please add...</reason></invite><invite to=\"6000059859@etop.com\"><reason>meeting...</reason></invite></x></message>"
"<iq id=\"5krX2-21\" to=\"conference.etop.com\" type=\"get\"><query xmlns=\"jabber:iq:load:rooms\" /></iq>",
"</stream:stream>"
};


int preOffset,preSize;
static void XMLCALL
start(void *data, const char *el, const char **attr)
{
  int i;
  test_connection_t *c=(test_connection_t*)data;
  req_ctx_t *ctx=(req_ctx_t*)c->data;
  for (i = 0; i < ctx->depth; i++)
    printf("\t");

  printf("%d: %s",ctx->depth, el);

  for (i = 0; attr[i]; i += 2) {
    printf(" %s='%s'", attr[i], attr[i + 1]);
  }

  printf("\n");
  if(ctx->depth==1){
	
        char *str=XML_GetInputContext(ctx->parser, &preOffset, &preSize);
        
        //printf("CurrentByteIndex:%d , CurrentByteCount:%d,  \n",preOffset,preSize);
  }
  
  ctx->depth++;
  
}

static void XMLCALL
end(void *data, const char *el)
{
  test_connection_t *c=(test_connection_t*)data;
  req_ctx_t *ctx=(req_ctx_t*)c->data;
  ctx->depth--;
  if(ctx->depth==1){
	int offset,size;
	char *str=XML_GetInputContext(ctx->parser, &offset, &size);
	size=offset-preOffset+strlen(el)+3;
	char *tmp=calloc(size,1);
	memcpy(tmp,str+preOffset,size);
	printf("pre-offset: %d, offset: %d, size: %d, depth: %d, %s, %s\n",preOffset, offset,size ,ctx->depth, tmp,el);
  }
}

int init_hand(test_connection_t *c){
     XML_Parser p = XML_ParserCreate(NULL);
     if (! p) {
        fprintf(stderr, "Couldn't allocate memory for parser\n");
        exit(-1);
     }
     
     req_ctx_t *ctx=calloc(1,sizeof(req_ctx_t));
     ctx->parser=p;
     ctx->depth=0;
     
     c->data=ctx;

     XML_SetUserData(p, c);
     XML_SetElementHandler(p, start, end);
     ssize_t n;
     int done;
     for(int i=0;i<7;i++){
        done=memcmp(packets[i],"</stream:stream>",16)==0?1:0;
        if (XML_Parse(p, packets[i], strlen(packets[i]), done) == XML_STATUS_ERROR) {
                int errCode=XML_GetErrorCode(p);
                if(errCode==36){
                        fprintf(stderr, " (%d) %s\n",
                        XML_GetErrorCode(p),
                        XML_ErrorString(XML_GetErrorCode(p)));
                }else{
                        fprintf(stderr, "Parse error at line %lu:(%d) %s\n",
                        XML_GetCurrentLineNumber(p),XML_GetErrorCode(p),
                        XML_ErrorString(XML_GetErrorCode(p)));
                }
                break;
        }
          //n=send_myself(send_fd,packets[i]);
          //          //if(n == NGX_ERROR)break;
          //                    //if(n == NGX_AGAIN){
          //                            //      n=send_myself(send_fd,packets[i]);
      }
     return 0;
}



int main(int argc, char** argv)
{
	ngx_str_t encrypted;
	//encrypted.data = b->last;

	rc = ngx_crypt_sha(c->pool, ctx->xml_streamid.data, ctx->xml_streamid.len,
					   &encrypted);

	ngx_log_debug3(NGX_LOG_DEBUG_HTTP, c->log, 0,
				   "rc: %d streamid: \"%s\" encrypted: \"%s\"",
				   rc, ctx->xml_streamid.data, encrypted.data);
	
	return 0;
//	cycle=init_nginx();
     int send_fd;
     struct sockaddr_in s_addr;
     socklen_t len = sizeof(s_addr);
     send_fd = socket(AF_INET, SOCK_STREAM, 0);
     if(send_fd == -1)
     {
          perror("socket failed  ");
          return -1;
     }
     int rcvbuf=4096;
     if (setsockopt(send_fd, SOL_SOCKET, SO_RCVBUF,
                       (const void *) &rcvbuf, sizeof(int)) == -1){
	 perror("set recvbuff failed  ");
	 return -1;
     }

     /*int nb=1;
     if(ioctl(send_fd, FIONBIO, &nb)==-1){
	  perror("nonblocking failed  ");
          return -1;
     }*/
     bzero(&s_addr, sizeof(s_addr));
     s_addr.sin_family = AF_INET;

     inet_pton(AF_INET,SER_IP,&s_addr.sin_addr);
     s_addr.sin_port = htons(SER_PORT);
     if(connect(send_fd,(struct sockaddr*)&s_addr,len) == -1)
     {
	  if(errno!=EINPROGRESS){
          	perror("connect fail  ");
		if(close(send_fd)==-1)perror("close fail  ");
          	return -1;
	  }
     }
     
     test_connection_t *c=(test_connection_t*)calloc(1,sizeof(test_connection_t));
     c->fd=send_fd;
     c->ev=NULL;
     c->hand=init_hand;
     test_epoll_init(c);
     
     test_epoll_add_connection(c);

     test_connection_t *lc=(test_connection_t*)calloc(1,sizeof(test_connection_t));
     lc->fd=-1;
     lc->hand=init_hand;
     for(;;)
     	test_process_events_and_timers(lc);
     return 0;
} 

