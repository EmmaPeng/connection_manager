/*
 * =====================================================================================
 *
 *       Filename:  test_epoll.c
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  03/03/2014 03:27:54 AM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  Humphery yu (), humphery.yu@gmail.com
 *   Organization:  
 *
 * =====================================================================================
 */

#include <ngx_config.h>
#include <ngx_core.h>

#include <test_socket.h>
#include <test_epoll.h>

int epfd=-1;
struct epoll_event  *event_list;
int      nevents;

sig_atomic_t          t_event_timer_alarm;
static void
t_timer_signal_handler(int signo)
{
    t_event_timer_alarm = 1;

}
void setnonblocking(int sock)
{
    int opts;
    opts=fcntl(sock,F_GETFL);
    if(opts<0)
    {
        perror("fcntl(sock,GETFL)");
        exit(1);
    }
    opts = opts|O_NONBLOCK;
    if(fcntl(sock,F_SETFL,opts)<0)
    {
        perror("fcntl(sock,SETFL,opts)");
        exit(1);
    }
}

void
test_process_events_and_timers(test_connection_t *lc)
{
    struct epoll_event ev;
    int nfds;
        //等待epoll事件的发生

        nfds=epoll_wait(epfd,event_list, nevents,500);
	int err = (nfds == -1) ? errno : 0;
	if(err){
		if (err == EINTR) {
			if(t_event_timer_alarm){
				t_event_timer_alarm=0;
				return;
			}
		}
		perror("epoll_wait() failed");
		return;
	}
	if (nfds == 0) {
		//printf("epoll_wait() returned no events without timeout\n");
		return;
	}
        //处理所发生的所有事件
        for(int i=0;i<nfds;++i)
        {

	    test_connection_t *c=event_list[i].data.ptr;
	    c = (test_connection_t *) ((uintptr_t) c & (uintptr_t) ~1);

            if(c->fd==lc->fd)//如果新监测到一个SOCKET用户连接到了绑定的SOCKET端口，建立新的连接。
            {
		struct sockaddr_in in_addr;
                socklen_t in_len;
                int connfd = accept4(lc->fd,(struct sockaddr *)&in_addr, &in_len,SOCK_NONBLOCK);
                if(connfd<0){
                    perror("connfd<0");
                    //exit(1);
                }
                setnonblocking(connfd);

                char *str = inet_ntoa(in_addr.sin_addr);
                printf( "%d  accapt a connection from %s \n",event_list[i].events, str);
                //设置用于读操作的文件描述符
                //设置用于注测的读操作事件

                ev.events=EPOLLIN|EPOLLET;
                //ev.events=EPOLLIN;
		test_connection_t *cnew=(test_connection_t*)calloc(1,sizeof(test_connection_t));
		cnew->hand=init_hand;
		cnew->fd=connfd;
		cnew->current=0;

		ev.data.ptr=cnew;
                //注册ev

                epoll_ctl(epfd,EPOLL_CTL_ADD,connfd,&ev);
            }
            else if((event_list[i].events&EPOLLIN) || (event_list[i].events&EPOLLOUT))//如果是已经连接的用户，并且收到数据，那么进行读入。
            {
                printf("EPOLLET | EPOLLOUT: %d\n",event_list[i].events);
		if(28 == event_list[i].events){
			perror("28");
			printf("%d\n",errno);
			//if(errno == ECONNRESET) return;//Connection reset by peer
			//else
				printf("epoll event: 28, errno: %d\n",errno);
			close(c->fd);
			free(c);
			return;
		}
		c->ev=&event_list[i];
		c->hand(c);

            }
            else { // 如果有数据发送
		perror("unknow event: ");
            }
        }
}

ngx_int_t test_epoll_init(test_connection_t *c){
    epfd=epoll_create(256);

    nevents=20;
    event_list=(struct epoll_event*)calloc(nevents,sizeof(struct epoll_event));
    if(c->ev){
	c->ev->data.ptr=(void *) ((uintptr_t) c | 1);
	if (epoll_ctl(epfd, EPOLL_CTL_ADD, c->fd, c->ev) == -1) {
        	perror("epoll_ctl(EPOLL_CTL_ADD ) failed");
        	return NGX_ERROR;
	}
    }
}

ngx_int_t test_epoll_add_connection(test_connection_t *c)
{
    struct epoll_event  ee;

    ee.events = EPOLLIN|EPOLLOUT|EPOLLET;
    ee.data.ptr = (void *) ((uintptr_t) c | 1);

    if (epoll_ctl(epfd, EPOLL_CTL_ADD, c->fd, &ee) == -1) {
        perror("epoll_ctl(EPOLL_CTL_ADD ) failed");
        return NGX_ERROR;
    }
//    c->read->active = 1;
  //  c->write->active = 1;
    return NGX_OK;
}


