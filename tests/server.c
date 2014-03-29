/*
 * =====================================================================================
 *
 *       Filename:  server.c
 *
 *    Description:  tcp server
 *
 *        Version:  1.0
 *        Created:  01/20/2014 04:33:03 AM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  Humphery yu (), humphery.yu@gmail.com
 *   Organization:  
 *
 * =====================================================================================
 */

/*#include <sys/types.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
*/
#include <ngx_config.h>
#include <ngx_core.h>
#include <expat.h>
#include <test_socket.h>
#include <packet.h>
#include <test_epoll.h>


#define MAXLINE 5
#define OPEN_MAX 100
#define LISTENQ 20
#define SERV_PORT 5000
#define INFTIM 1000
ssize_t PACKET_HEAD_LEN=sizeof(packet_head);

//static ngx_uint_t           nevents;
//static struct epoll_event  *event_list;

static u_char packets[6][40960]={
"<?xml version='1.0' encoding='UTF-8'?><stream:stream xmlns:stream=\"http://etherx.jabber.org/streams\" xmlns=\"jabber:client\" from=\"etop.com\" id=\"91674286\" xml:lang=\"en\" version=\"1.0\"><stream:features><mechanisms xmlns=\"urn:ietf:params:xml:ns:xmpp-sasl\"><mechanism>AASAUTH</mechanism></mechanisms><compression xmlns=\"http://jabber.org/features/compress\"><method>zlib</method></compression><auth xmlns=\"http://jabber.org/features/iq-auth\"/><register xmlns=\"http://jabber.org/features/iq-register\"/></stream:features>",
"<success xmlns=\"urn:ietf:params:xml:ns:xmpp-sasl\" jid=\"6000063742@etop.com/easier\"/>",
"<presence to=\"6001738977@etop.com/Spark 2.6.3\" from=\"111223@conference.etop.com/6001738977\"><x xmlns=\"http://jabber.org/protocol/muc#user\"><item affiliation=\"owner\" jid=\"6001738977@etop.com\" nick=\"6001738977\" role=\"moderator\"><reason/> <actor jid=\"/> </item> <status code=\"201\"/></x></presence>",
"<iq id=\"5krX2-21\" to=\"6000059759@etop.com/Spark 2.6.3\" type=\"result\" from=\"conference.etop.com\"> <query xmlns=\"jabber:iq:load:rooms\"><item jid=\"112233@conference.etop.com\" name=\"groups\"/></query></iq>",
"<message id=\"5YUme-47\" from=\"333333@conference.etop.com\" to=\"6000059759@etop.com/Spark 2.6.3\" type=\"error\"> <x xmlns=\"http://jabber.org/protocol/muc#user\"> <invite to=\"6000055759@etop.com\"> <reason>metting … </reason>   </invite>  </x><error code=\"400\" type=\"modify\"><bad-request xmlns=\"urn:ietf:params:xml:ns:xmpp-stanzas\"/></error></message>"
};

u_char line[MAXLINE];
int write_hand(test_connection_t *c);
int read_hand(test_connection_t *c);

int read_hand(test_connection_t *c){
	struct epoll_event ev;
	ssize_t n;
	u_char* sbuf;
	sbuf=(u_char*)calloc((size_t)409600,sizeof(u_char));
	int index=0;
	do{
		n = test_unix_recv(c,line,MAXLINE);
       	        //line[n] = '\0';

       	        if(n>0){
			memcpy(sbuf+index,(char*)line,n);
			index+=n;
		}else if(n == NGX_ERROR || c->eof == 1){
			close(c->fd);
	                c->fd=-1;
        	        free(c);
                	return -1;
		}else
			break;

		if (n <MAXLINE) break;
                //cout  << strdata << endl;
	}while(n>0);

	if(n!=0 && (n < MAXLINE || errno ==11)){
		printf("read_hand: %d, current: %d, %s \n",index ,c->current,sbuf);
		req_ctx_t *ctx=(req_ctx_t*)c->data;
		XML_Parser p=ctx->parser;

		if (XML_Parse(p, sbuf, strlen(sbuf), 0) == XML_STATUS_ERROR) {
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
        	}
		struct epoll_event ev;
		ev.data.ptr=c;
		ev.events=EPOLLIN|EPOLLET;
		c->hand=read_hand;
		ngx_queue_t       *q,*cache=&ctx->cw_queue;
		xmpp_packet_t *packet;
		for (q = ngx_queue_head(cache);q && q != ngx_queue_sentinel(cache); q = ngx_queue_next(q))
    		{
			packet = ngx_queue_data(q, xmpp_packet_t , queue);
			switch(packet->msg_type){
				case 1:
				case 2:
				case 3:
				case 4:
					ev.events=EPOLLOUT|EPOLLET;
					c->hand=write_hand;
					goto process;
				case 5:
					ngx_queue_remove(q);
				default:
					ev.events=EPOLLIN|EPOLLET;
					c->hand=read_hand;
					break;
			}
		}
	process:
		epoll_ctl(epfd,EPOLL_CTL_MOD,c->fd,&ev);
	}
	return 0;
}

int preOffset,preSize;
static void XMLCALL
__start(void *data, const char *el, const char **attr)
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
	xmpp_packet_t *packet=calloc(1,sizeof(xmpp_packet_t));
	ctx->packet=packet;
        char *str=XML_GetInputContext(ctx->parser, &preOffset, &preSize);
 }
 else if(ctx->depth==0){
	char *str=XML_GetInputContext(ctx->parser, &preOffset, &preSize);

	char *sbuf=calloc(strlen(str),1);
	memcpy(sbuf,str,strlen(str));
	xmpp_packet_t *packet=calloc(1,sizeof(xmpp_packet_t));
	packet->data.data=sbuf;
	packet->data.len=strlen(sbuf);

	if(strcspn(el,"stream:stream")>=0)packet->msg_type=1;
	else packet->msg_type=0;
	ngx_queue_insert_tail(&ctx->cw_queue,&packet->queue);
 }

  ctx->depth++;

}

static void XMLCALL
__end(void *data, const char *el)
{
  test_connection_t *c=(test_connection_t*)data;
  req_ctx_t *ctx=(req_ctx_t*)c->data;
  ctx->depth--;

  if( ctx->depth==1){
	int offset,size;
	char *str=XML_GetInputContext(ctx->parser, &offset, &size);
	size=offset-preOffset+strlen(el)+3;
	char *sbuf=calloc(size,1);
	memcpy(sbuf,str+preOffset,size);

	xmpp_packet_t *packet=ctx->packet;
	packet->data.data=sbuf;
	packet->data.len=strlen(sbuf);
	ngx_queue_insert_tail(&ctx->cw_queue,&packet->queue);
//	printf("pre-offset: %d, offset: %d, size: %d, depth: %d, %s, %s\n",preOffset, offset,size ,ctx->depth, sbuf,el);
   }else if( ctx->depth==2){
	xmpp_packet_t *packet=ctx->packet;
	if(strcmp(el,"iq")==0) packet->msg_type=2;
        else if(strcmp(el,"presence")==0) packet->msg_type=3;
        else if(strcmp(el,"auth")==0) packet->msg_type=4;
        else if(strcmp(el,"message")==0) packet->msg_type=5;
        else if(strcmp(el,"stream:stream")==0) packet->msg_type=1;
        else packet->msg_type==0;
   }
}

int init_hand(test_connection_t *c){
     XML_Parser p = XML_ParserCreate(NULL);
     if (! p) {
        fprintf(stderr, "Couldn't allocate memory for parser\n");
        exit(-1);
     }

     req_ctx_t *ctx=calloc(1,sizeof(req_ctx_t));
     ngx_queue_init(&ctx->uw_queue);
     ngx_queue_init(&ctx->cw_queue);
     ctx->parser=p;
     ctx->depth=0;

     c->data=ctx;

     XML_SetUserData(p, c);
     XML_SetElementHandler(p, __start, __end);
	c->hand=read_hand;
	return c->hand(c);
}
int write_hand(test_connection_t *c){
	struct epoll_event ev;
	ssize_t n;
	req_ctx_t *ctx=(req_ctx_t *)c->data;
        //u_char packet[10240];//=(char*)"%d<stream test=0000";
                //sprintf(packet,"%d.%d:<stream test=0000",top_counter,counter);
       ngx_queue_t       *q,*cache=&ctx->cw_queue;
       xmpp_packet_t *packet;
       for (q = ngx_queue_head(cache);q && q != ngx_queue_sentinel(cache); q = ngx_queue_next(q))
       {
                packet = ngx_queue_data(q, xmpp_packet_t , queue);
		ngx_queue_remove(q);
	        n = test_unix_send(c,packet->data.data, packet->data.len);
		if(n == NGX_ERROR){
			close(c->fd);
			c->fd=-1;

			free(c);
			return -1;
		}
	}
                //设置用于读操作的文件描述符
	ev.data.ptr=c;
	c->hand=read_hand;
                //设置用于注测的读操作事件

        ev.events=EPOLLIN|EPOLLET;
                //修改sockfd上要处理的事件为EPOLIN

       	epoll_ctl(epfd,EPOLL_CTL_MOD,c->fd,&ev);
	return 0;
}

sig_atomic_t          t_event_timer_alarm;
static void
t_timer_signal_handler(int signo)
{
    t_event_timer_alarm = 1;

    //ngx_log_debug0(NGX_LOG_DEBUG_EVENT, ngx_cycle->log, 0, "timer signal");
}
/*
void pro_signal(){
	struct sigaction  sa;
        struct itimerval  itv;

        memset(&sa,0, sizeof(struct sigaction));
        sa.sa_handler = ngx_timer_signal_handler;
        sigemptyset(&sa.sa_mask);

        if (sigaction(SIGALRM, &sa, NULL) == -1) {
            perror("sigaction(SIGALRM) failed");
            return ;
        }
	int ngx_timer_resolution = 10000*10;
        itv.it_interval.tv_sec = ngx_timer_resolution / 1000;
        itv.it_interval.tv_usec = (ngx_timer_resolution % 1000) * 1000;
        itv.it_value.tv_sec = ngx_timer_resolution / 1000;
        itv.it_value.tv_usec = (ngx_timer_resolution % 1000 ) * 1000;

        if (setitimer(ITIMER_REAL, &itv, NULL) == -1) {
            perror("setitimer() failed");
        }
}
*/

int main(int argc, char* argv[])
{
    int i, maxi, listenfd, connfd, nfds, portnumber;
    socklen_t clilen;


    if ( 2 == argc )
    {
        if( (portnumber = atoi(argv[1])) < 0 )
        {
            fprintf(stderr,"Usage:%s portnumber\n",argv[0]);
            return 1;
        }
    }
    else
    {
        fprintf(stderr,"Usage:%s portnumber\n",argv[0]);
        return 1;
    }



    //声明epoll_event结构体的变量,ev用于注册事件,数组用于回传要处理的事件

    //生成用于处理accept的epoll专用的文件描述符

    struct sockaddr_in clientaddr;
    struct sockaddr_in serveraddr;
    listenfd = socket(AF_INET, SOCK_STREAM, 0);
    //把socket设置为非阻塞方式

    setnonblocking(listenfd);

    //设置与要处理的事件相关的文件描述符

    test_connection_t *c_=(test_connection_t*)calloc(1,sizeof(test_connection_t));
    c_->hand=init_hand;
    c_->fd=listenfd;

    struct epoll_event ev;
    ev.data.ptr=(void *) ((uintptr_t) c_);
    //设置要处理的事件类型
    //ev.data.fd=listenfd;

    ev.events=EPOLLIN|EPOLLET;
    //ev.events=EPOLLIN;
    c_->ev=&ev;
    //注册epoll事件

    memset(&serveraddr,0, sizeof(serveraddr));
    serveraddr.sin_family = AF_INET;
    const char *local_addr="127.0.0.1";
    inet_aton(local_addr,&(serveraddr.sin_addr));//htons(portnumber);

    serveraddr.sin_port=htons(portnumber);
    bind(listenfd,(struct sockaddr *)&serveraddr, sizeof(serveraddr));
    listen(listenfd, LISTENQ);
    maxi = 0;
    test_epoll_init(c_);
    for(;;){
		test_process_events_and_timers(c_);
    }
    return 0;
}

