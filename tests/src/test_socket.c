/*
 * =====================================================================================
 *
 *       Filename:  socket.c
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  03/01/2014 11:45:15 AM
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
#include <nginx.h>

//#include <stdlib.h>
//#include <stdio.h>
//#include <errno.h>
//#include <sys/types.h>
//#include <sys/socket.h>
//#include <sys/ioctl.h>
#include <test_socket.h>


ssize_t test_unix_recv (test_connection_t *c, u_char *buf, size_t size ){
     ssize_t n;
     do {
	n = recv(c->fd,buf,size,0);

     	if(n > 0)
		return n;

     	if(n  == 0)
     	{
	  //if(errno == EAGAIN)printf("EAGAIN"); 
	  if(errno == ECONNRESET){
               return NGX_ERROR; 
          }
	  if(errno){ 
		perror("read serv fail");
          	printf("errno: %d\n",errno);
		return NGX_ERROR;//check....
	  }
          c->eof=1;
          return n;
     	}

     	if (errno == EAGAIN || errno == EINTR){
		perror("recv() not ready");
		n=NGX_AGAIN;
     	}else if(errno){
		perror("recv() failed");
		return NGX_ERROR;
     	}
    } while (errno == EINTR);
    return n;
}

ssize_t test_unix_send(test_connection_t *c, u_char *buf, size_t size)
{
     ssize_t       n;
     do{
     n=send(c->fd,buf, size,0);
     if (n > 0) {
        if (n < (ssize_t) size) printf("size is %zd\n",n);
        return n;
     }
     if (n == 0) {
        perror("send() returned zero  ");
	return -1;
     }
     if(errno == EAGAIN || errno == EINTR){
        perror("send() not ready ");
	if(errno == EAGAIN)return NGX_AGAIN;
     }else{
        perror("send() failed ");
	return NGX_ERROR;
     }
     }while(1);
     return -1;
}


