
#ifndef _NGX_TCP_SESSION_H_INCLUDED_
#define _NGX_TCP_SESSION_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_event_connect.h>
#include <ngx_tcp.h>
#include <expat.h>


typedef void (*ngx_tcp_cleanup_pt)(void *data);


struct ngx_tcp_cleanup_s {
    ngx_tcp_cleanup_pt      handler;
    void                   *data;
    ngx_tcp_cleanup_t      *next;
};



void ngx_tcp_send(ngx_event_t *wev);
ngx_int_t ngx_tcp_read_command(ngx_tcp_session_t *s, ngx_connection_t *c);
void ngx_tcp_auth(ngx_tcp_session_t *s, ngx_connection_t *c);
void ngx_tcp_close_connection(ngx_connection_t *c);
void ngx_tcp_session_internal_server_error(ngx_tcp_session_t *s);

void ngx_tcp_finalize_session(ngx_tcp_session_t *s);

ngx_tcp_cleanup_t * ngx_tcp_cleanup_add(ngx_tcp_session_t *s, size_t size);


#endif
