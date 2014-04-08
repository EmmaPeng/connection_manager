

#ifndef _NGX_XMPP_CONNECTION_POOL_H_INCLUDED_
#define _NGX_XMPP_CONNECTION_POOL_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_hashtable.h>

typedef struct ngx_tcp_connection_pool_s ngx_tcp_connection_pool_t;


typedef struct {
    //ngx_queue_t              queue;
    //ngx_connection_t        *connection;
	ngx_uint_t				last_cached;
    socklen_t               socklen;
    u_char                  sockaddr[NGX_SOCKADDRLEN];
    ngx_peer_connection_t   **cached;
} ngx_tcp_connection_pool_elt_t;


struct ngx_tcp_connection_pool_s {
    //ngx_queue_t             *cache;
    //ngx_queue_t             *free;
    ngx_uint_t               max_cached;
    ngx_uint_t               bucket_count;

    ngx_uint_t               failed;       /* unsigned:1 */
    ngx_pool_t              *pool;
	ngx_hashtable_t			*hashtable;
	void					*data;
	

#if (NGX_DEBUG)
    ngx_int_t                count;        /* check get&free op pairs */
#endif

    ngx_event_get_peer_pt    get_peer;
    ngx_event_free_peer_pt   free_peer;
	ngx_tcp_upstream_srv_conf_t *uscf;
};

ngx_tcp_connection_pool_t *ngx_tcp_connection_pool_init(ngx_pool_t *pool, ngx_tcp_conf_ctx_t *cf);
void ngx_xmpp_upstream_connect_finished(ngx_xmpp_upstream_ctx_t *ctx);
void ngx_xmpp_proxy_event_delete(ngx_xmpp_upstream_ctx_t *ctx,ngx_event_t *ev);
void ngx_xmpp_proxy_event_add(ngx_xmpp_upstream_ctx_t *ctx,ngx_event_t *ev);

#endif /* _NGX_TCP_SSL_H_INCLUDED_ */
