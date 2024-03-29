
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_hashtable.h>
#include <ngx_tcp_xmpp.h>

static void ngx_tcp_upstream_cleanup(void *data);

static void ngx_tcp_upstream_handler(ngx_event_t *ev); 
static void ngx_tcp_upstream_connect(ngx_tcp_session_t *s,
    ngx_tcp_upstream_t *u);
static void ngx_tcp_upstream_resolve_handler(ngx_resolver_ctx_t *ctx);
static void ngx_tcp_upstream_finalize_session(ngx_tcp_session_t *s,
    ngx_tcp_upstream_t *u, ngx_int_t rc);

static char *ngx_tcp_upstream(ngx_conf_t *cf, ngx_command_t *cmd, void *dummy);
static char *ngx_tcp_upstream_server(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_tcp_upstream_check(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

static void *ngx_tcp_upstream_create_main_conf(ngx_conf_t *cf);
static char *ngx_tcp_upstream_init_main_conf(ngx_conf_t *cf, void *conf);

static char *ngx_tcp_upstream_connections(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_tcp_upstream_keepalive_timeout(ngx_conf_t *cf, ngx_command_t *cmd,void *conf);
static char * ngx_tcp_upstream_buffer_size(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

ngx_tcp_connection_pool_t		*CONN_POOL;

static ngx_conf_bitmask_t  ngx_check_http_expect_alive_masks[] = {
    { ngx_string("http_2xx"), NGX_CHECK_HTTP_2XX },
    { ngx_string("http_3xx"), NGX_CHECK_HTTP_3XX },
    { ngx_string("http_4xx"), NGX_CHECK_HTTP_4XX },
    { ngx_string("http_5xx"), NGX_CHECK_HTTP_5XX },
    { ngx_null_string, 0 }
};

static ngx_conf_bitmask_t  ngx_check_smtp_expect_alive_masks[] = {
    { ngx_string("smtp_2xx"), NGX_CHECK_SMTP_2XX },
    { ngx_string("smtp_3xx"), NGX_CHECK_SMTP_3XX },
    { ngx_string("smtp_4xx"), NGX_CHECK_SMTP_4XX },
    { ngx_string("smtp_5xx"), NGX_CHECK_SMTP_5XX },
    { ngx_null_string, 0 }
};

static ngx_command_t  ngx_tcp_upstream_commands[] = {

    { ngx_string("upstream"),
      NGX_TCP_MAIN_CONF|NGX_CONF_BLOCK|NGX_CONF_TAKE1,
      ngx_tcp_upstream,
      0,
      0,
      NULL },

    { ngx_string("server"),
      NGX_TCP_UPS_CONF|NGX_CONF_1MORE,
      ngx_tcp_upstream_server,
      NGX_TCP_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("check"),
      NGX_TCP_UPS_CONF|NGX_CONF_1MORE,
      ngx_tcp_upstream_check,
      NGX_TCP_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("check_http_send"),
      NGX_TCP_UPS_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_TCP_SRV_CONF_OFFSET,
      offsetof(ngx_tcp_upstream_srv_conf_t, send),
      NULL },

    { ngx_string("check_smtp_send"),
      NGX_TCP_UPS_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_TCP_SRV_CONF_OFFSET,
      offsetof(ngx_tcp_upstream_srv_conf_t, send),
      NULL },

    { ngx_string("check_http_expect_alive"),
      NGX_TCP_UPS_CONF|NGX_CONF_1MORE,
      ngx_conf_set_bitmask_slot,
      NGX_TCP_SRV_CONF_OFFSET,
      offsetof(ngx_tcp_upstream_srv_conf_t, code.status_alive),
      &ngx_check_http_expect_alive_masks },

    { ngx_string("check_smtp_expect_alive"),
      NGX_TCP_UPS_CONF|NGX_CONF_1MORE,
      ngx_conf_set_bitmask_slot,
      NGX_TCP_SRV_CONF_OFFSET,
      offsetof(ngx_tcp_upstream_srv_conf_t, code.status_alive),
      &ngx_check_smtp_expect_alive_masks },

    { ngx_string("check_shm_size"),
      NGX_TCP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_TCP_MAIN_CONF_OFFSET,
      offsetof(ngx_tcp_upstream_main_conf_t, check_shm_size),
      NULL },

	{ ngx_string("connections"),
      NGX_TCP_UPS_CONF|NGX_CONF_TAKE12,
      ngx_tcp_upstream_connections,
      0,
      0,
      NULL },

	{ ngx_string("keepalive_timeout"),
      NGX_TCP_UPS_CONF|NGX_CONF_TAKE1,
      ngx_tcp_upstream_keepalive_timeout,
      0,
      0,
      NULL },
  
	{ ngx_string("buffer_size"),
      NGX_TCP_UPS_CONF|NGX_CONF_TAKE1,
      ngx_tcp_upstream_buffer_size,
      0,
      0,
      NULL },
  
	{ ngx_string("server_name"),
      NGX_TCP_UPS_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_TCP_SRV_CONF_OFFSET,
      offsetof(ngx_tcp_upstream_srv_conf_t, server_name),
      NULL },
    ngx_null_command
};


static ngx_tcp_module_t  ngx_tcp_upstream_module_ctx = {
    NULL,

    ngx_tcp_upstream_create_main_conf,     /* create main configuration */
    ngx_tcp_upstream_init_main_conf,       /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */
};


ngx_module_t  ngx_tcp_upstream_module = {
    NGX_MODULE_V1,
    &ngx_tcp_upstream_module_ctx,          /* module context */
    ngx_tcp_upstream_commands,             /* module directives */
    NGX_TCP_MODULE,                        /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


ngx_int_t
ngx_tcp_upstream_create(ngx_tcp_session_t *s) 
{
    ngx_tcp_upstream_t  *u;

    u = s->upstream;

    if (u && u->cleanup) {
        ngx_tcp_upstream_cleanup(s);
    }

    u = ngx_pcalloc(s->pool, sizeof(ngx_tcp_upstream_t));
    if (u == NULL) {
        return NGX_ERROR;
    }

    s->upstream = u;


    return NGX_OK;
}


void
ngx_tcp_upstream_init(ngx_tcp_session_t *s)
{
    ngx_str_t                      *host;
    ngx_uint_t                      i;
    ngx_connection_t               *c;
    ngx_tcp_cleanup_t              *cln;
    ngx_resolver_ctx_t             *ctx, temp;
    ngx_tcp_upstream_t             *u;
    ngx_tcp_core_srv_conf_t        *cscf;
    ngx_tcp_upstream_srv_conf_t    *uscf, **uscfp;
    ngx_tcp_upstream_main_conf_t   *umcf;

    c = s->connection;

    cscf = ngx_tcp_get_module_srv_conf(s, ngx_tcp_core_module);

    ngx_log_debug1(NGX_LOG_DEBUG_TCP, c->log, 0,
                   "tcp init upstream, client timer: %d", c->read->timer_set);

    if (c->read->timer_set) {
        ngx_del_timer(c->read);
    }

    u = s->upstream;

    cln = ngx_tcp_cleanup_add(s, 0);

    cln->handler = ngx_tcp_upstream_cleanup;
    cln->data = s;
    u->cleanup = &cln->handler;

    if (u->resolved == NULL) {

        uscf = u->conf->upstream;

    } else {

        /*TODO: support variable in the proxy_pass*/
        if (u->resolved->sockaddr) {

            if (ngx_tcp_upstream_create_round_robin_peer(s, u->resolved)
                != NGX_OK)
            {
                ngx_tcp_finalize_session(s);
                return ;
            }

            ngx_tcp_upstream_connect(s, u);

            return;
        }

        host = &u->resolved->host;

        umcf = ngx_tcp_get_module_main_conf(s, ngx_tcp_upstream_module);

        uscfp = umcf->upstreams.elts;

        for (i = 0; i < umcf->upstreams.nelts; i++) {

            uscf = uscfp[i];

            if (uscf->host.len == host->len
                && ((uscf->port == 0 && u->resolved->no_port)
                    || uscf->port == u->resolved->port)
                && ngx_memcmp(uscf->host.data, host->data, host->len) == 0)
            {
                goto found;
            }
        }

        temp.name = *host;

        ctx = ngx_resolve_start(cscf->resolver, &temp);
        if (ctx == NULL) {
            ngx_tcp_finalize_session(s);
            return;
        }

        if (ctx == NGX_NO_RESOLVER) {
            ngx_log_error(NGX_LOG_ERR, c->log, 0,
                         "no resolver defined to resolve %V", host);
            ngx_tcp_finalize_session(s);
            return;
        }

        ctx->name = *host;
#if (nginx_version) < 1005008
        ctx->type = NGX_RESOLVE_A;
#endif
        ctx->handler = ngx_tcp_upstream_resolve_handler;
        ctx->data = s;
        ctx->timeout = cscf->resolver_timeout;

        u->resolved->ctx = ctx;

        if (ngx_resolve_name(ctx) != NGX_OK) {
            u->resolved->ctx = NULL;
            ngx_tcp_finalize_session(s);
            return;
        }

        return;
    }

found:

    if (uscf->peer.init(s, uscf) != NGX_OK) {
        ngx_tcp_finalize_session(s);
        return;
    }

    ngx_tcp_upstream_connect(s, u);
	//ngx_tcp_upstream_init_proxy_handler(s,s->upstream);
}


static void
ngx_tcp_upstream_resolve_handler(ngx_resolver_ctx_t *ctx) 
{
    ngx_tcp_session_t            *s;
    ngx_tcp_upstream_resolved_t  *ur;

    s = ctx->data;

    s->upstream->resolved->ctx = NULL;

    if (ctx->state) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                      "%V could not be resolved (%i: %s)",
                      &ctx->name, ctx->state,
                      ngx_resolver_strerror(ctx->state));

        ngx_resolve_name_done(ctx);
        ngx_tcp_finalize_session(s);
        return;
    }

    ur = s->upstream->resolved;
    ur->naddrs = ctx->naddrs;
    ur->addrs = ctx->addrs;

#if (NGX_DEBUG)
    {
#if (nginx_version) >= 1005008
        u_char      text[NGX_SOCKADDR_STRLEN];
        ngx_str_t   addr;
#else
        in_addr_t   addr;
#endif
        ngx_uint_t  i;

#if (nginx_version) >= 1005008
        addr.data = text;
#endif

        for (i = 0; i < ctx->naddrs; i++) {
#if (nginx_version) >= 1005008
            addr.len = ngx_sock_ntop(ur->addrs[i].sockaddr, ur->addrs[i].socklen,
                                     text, NGX_SOCKADDR_STRLEN, 0);

            ngx_log_debug1(NGX_LOG_DEBUG_TCP, s->connection->log, 0,
                           "name was resolved to %V", &addr);
#else
            addr = ntohl(ur->addrs[i]);

            ngx_log_debug4(NGX_LOG_DEBUG_TCP, s->connection->log, 0,
                           "name was resolved to %ud.%ud.%ud.%ud",
                           (addr >> 24) & 0xff, (addr >> 16) & 0xff,
                           (addr >> 8) & 0xff, addr & 0xff);
#endif
        }
    }
#endif

    if (ngx_tcp_upstream_create_round_robin_peer(s, ur) != NGX_OK) {
        ngx_resolve_name_done(ctx);
        ngx_tcp_finalize_session(s);
        return;
    }

    ngx_resolve_name_done(ctx);

    ngx_tcp_upstream_connect(s, s->upstream);
}

static void
ngx_tcp_upstream_connect(ngx_tcp_session_t *s, ngx_tcp_upstream_t *u) 
{
    int                       tcp_nodelay;
    ngx_int_t                 rc;
    ngx_connection_t         *c;
    ngx_tcp_core_srv_conf_t  *cscf;
	ngx_peer_connection_t	 *peer;

    s->connection->log->action = "connecting to upstream";

    cscf = ngx_tcp_get_module_srv_conf(s, ngx_tcp_core_module);

	CONN_POOL->data=u->conf;
	peer = u->peer;

	rc = CONN_POOL->get_peer((ngx_peer_connection_t*)&peer,CONN_POOL);
    //rc = ngx_tcp_upstream_connect_peer(s,u);//ngx_event_connect_peer(&u->peer);

    ngx_log_debug1(NGX_LOG_DEBUG_TCP, s->connection->log, 0,
                   "tcp upstream connect: %d", rc);

    if (rc != NGX_OK && rc != NGX_AGAIN ) {

        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, 
                      "upstream servers are busy or encounter error!");

        /* TODO: check this function */
        ngx_tcp_finalize_session(s);

        return;
    }

	u->peer = peer;
    /* rc == NGX_OK or rc == NGX_AGAIN */

    if (u->peer->check_index != (ngx_uint_t)NGX_INVALID_CHECK_INDEX) {
        ngx_tcp_check_get_peer(u->peer->check_index);
    }

    c = u->peer->connection;

	//TODO: c->data  ==>  ngx_xmpp_upstream_ctx_t
    //c->data = s;
	//TODO: c->pool 保持不变
    //c->pool = s->connection->pool;
    //c->log = s->connection->log;
    //c->read->log = c->log;
    //c->write->log = c->log;

    c->write->handler = ngx_tcp_upstream_handler;
    c->read->handler = ngx_tcp_upstream_handler;

    if (cscf->tcp_nodelay) {
        tcp_nodelay = 1;

        if (setsockopt(c->fd, IPPROTO_TCP, TCP_NODELAY,
                       (const void *) &tcp_nodelay, sizeof(int)) == -1)
        {
            ngx_connection_error(c, ngx_socket_errno,
                                 "setsockopt(TCP_NODELAY) failed");
            ngx_tcp_finalize_session(s);
            return;
        }

        c->tcp_nodelay = NGX_TCP_NODELAY_SET;
    }

    if (rc == NGX_AGAIN) {
        ngx_add_timer(c->write, u->conf->connect_timeout);
		//s->upstream->peer=NULL;
        //
    }
    else {
        ngx_add_timer(c->read, u->conf->read_timeout);
        ngx_add_timer(c->write, u->conf->send_timeout);

        c->write->handler(c->write);
		//s->connection->read->handler(s->connection->read);
    }
	
	if(u->read_event_handler){
		u->read_event_handler(s,s->upstream);
	}
}

static void
ngx_xmpp_upstream_connect(ngx_xmpp_upstream_ctx_t *ctx) 
{
    int                       tcp_nodelay;
    ngx_int_t                 rc;
    ngx_connection_t         *c;
    //ngx_tcp_core_srv_conf_t  *cscf;
	ngx_peer_connection_t	 *peer;
	//ngx_tcp_upstream_rr_peer_data_t  *rrp;

    //s->connection->log->action = "connecting to upstream";

    //cscf = ngx_tcp_get_module_srv_conf(s, ngx_tcp_core_module);

	CONN_POOL->data=ctx->conf;
	peer = &ctx->peer;
	
	/*
	rrp = peer->data;
	rrp->current = 0;

    if (rrp->peers->number <= 8 * sizeof(uintptr_t)) {
        rrp->tried = &rrp->data;
        rrp->data = 0;

    } else {
        n = (rrp->peers->number + (8 * sizeof(uintptr_t) - 1))
			/ (8 * sizeof(uintptr_t));

        rrp->tried = ngx_pcalloc(s->pool, n * sizeof(uintptr_t));
        if (rrp->tried == NULL) {
            return NGX_ERROR;
        }
    }
*/
	/*
    //peer->log = ctx->log;
    peer->log_error = NGX_ERROR_ERR;
    peer->get = ngx_tcp_upstream_get_round_robin_peer;
    peer->free = ngx_tcp_upstream_free_round_robin_peer;
    peer->tries = rrp->peers->number;
    peer->check_index = NGX_INVALID_CHECK_INDEX;
    peer->name = NULL;
#if (NGX_TCP_SSL)
    s->upstream->peer->set_session =
		ngx_tcp_upstream_set_round_robin_peer_session;
    s->upstream->peer->save_session =
		ngx_tcp_upstream_save_round_robin_peer_session;
#endif
*/

	rc = CONN_POOL->get_peer((ngx_peer_connection_t*)&peer,CONN_POOL);
    //rc = ngx_tcp_upstream_connect_peer(s,u);//ngx_event_connect_peer(&u->peer);

    ngx_log_debug1(NGX_LOG_DEBUG_TCP, peer->log, 0,
                   "tcp upstream connect: %d", rc);

	c = peer->connection;
    if (rc != NGX_OK && rc != NGX_AGAIN ) {

        ngx_log_error(NGX_LOG_ERR, peer->log, 0, 
                      "upstream servers are busy or encounter error!");

        /* TODO: check this function */
        ngx_tcp_upstream_close(c);

        return;
    }
	
	
    /* rc == NGX_OK or rc == NGX_AGAIN */

    if (peer->check_index != (ngx_uint_t)NGX_INVALID_CHECK_INDEX) {
        ngx_tcp_check_get_peer(peer->check_index);
    }

    c->write->handler = ngx_tcp_upstream_handler;
    c->read->handler = ngx_tcp_upstream_handler;

   // if (cscf->tcp_nodelay) {
       // tcp_nodelay = 1;

	if (setsockopt(c->fd, IPPROTO_TCP, TCP_NODELAY,
				   (const void *) &tcp_nodelay, sizeof(int)) == -1)
	{
		ngx_connection_error(c, ngx_socket_errno,
							 "setsockopt(TCP_NODELAY) failed");
		ngx_tcp_upstream_close(c);
		return;
	}

	c->tcp_nodelay = NGX_TCP_NODELAY_SET;
   // }

    if (rc == NGX_AGAIN) {
        ngx_add_timer(c->write, ctx->conf->connect_timeout);
        return;
    }
    else {
        ngx_add_timer(c->read, ctx->conf->read_timeout);
        ngx_add_timer(c->write, ctx->conf->send_timeout);

        c->write->handler(c->write);
		//s->connection->read->handler(s->connection->read);
    }
	
	//ngx_tcp_upstream_handler(ctx->ev);

}


static void
ngx_tcp_upstream_handler(ngx_event_t *ev) 
{
    ngx_connection_t     *c;
    //ngx_tcp_session_t    *s;
    //ngx_tcp_upstream_t   *u;
	
	ngx_xmpp_upstream_ctx_t *ctx;

    c = ev->data;
    ctx = c->data;
	ctx->ev = ev;
   // u = s->upstream;
    //c = s->connection;
	
	c->read->handler = ngx_xmpp_upstream_handler;
    c->write->handler = ngx_xmpp_upstream_handler;

    c->log->action = "ngx_tcp_upstream_init_proxy_handler";

    ngx_log_debug0(NGX_LOG_DEBUG_TCP, c->log, 0,
                   "xmpp proxy upstream init proxy");

    if (c->read->timedout || c->write->timedout) {
        ngx_tcp_upstream_next(ctx, NGX_TCP_UPSTREAM_FT_TIMEOUT);
        return;
    }

	//humphery
    if (ngx_tcp_upstream_check_broken_connection(c) != NGX_OK){
        ngx_tcp_upstream_next(ctx, NGX_TCP_UPSTREAM_FT_ERROR);
        return;
    }
	
	if(ev->ready){
		c->write->handler(ev);
	}else{
		//ngx_xmpp_upstream_handler(ev);
		ngx_add_timer(c->read, ctx->conf->read_timeout);
		ngx_add_timer(c->write, ctx->conf->send_timeout);
	}

}


ngx_int_t 
ngx_tcp_upstream_check_broken_connection(ngx_connection_t *c) 
{
    int                  n;
    char                 buf[1];
    ngx_err_t            err;

    if (c == NULL) {
        return NGX_ERROR;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_TCP, c->log, 0,
                   "tcp upstream check upstream, fd: %d", c->fd);

    n = recv(c->fd, buf, 1, MSG_PEEK);

    err = ngx_socket_errno;

    ngx_log_debug1(NGX_LOG_DEBUG_TCP, c->log, err,
                   "tcp check upstream recv(): %d", n);

    if (n >= 0 || err == NGX_EAGAIN) {
        return NGX_OK;
    }

    c->error = 1;

    return NGX_ERROR;
}

/*
void
ngx_tcp_upstream_next(ngx_tcp_session_t *s, ngx_tcp_upstream_t *u,
    ngx_uint_t ft_type) */
void
ngx_tcp_upstream_next(ngx_xmpp_upstream_ctx_t *ctx,
					  ngx_uint_t ft_type) 
{
	ngx_connection_t     *c;
	
	c = ctx->peer.connection;
	
    ngx_log_debug1(NGX_LOG_DEBUG_TCP, ctx->peer.log, 0,
                   "tcp next upstream, fail_type: %xi", ft_type);

    if (ft_type != NGX_TCP_UPSTREAM_FT_NOLIVE) {
        ctx->peer.free(&ctx->peer, ctx->peer.data, NGX_PEER_FAILED);
    }

    if (ft_type == NGX_TCP_UPSTREAM_FT_TIMEOUT) {
        ngx_log_error(NGX_LOG_ERR, ctx->peer.log, NGX_ETIMEDOUT,
                      "upstream timed out");
    }

    if (c->error) {
        ngx_tcp_upstream_close(c);
        return;
    }

    if (ctx->peer.tries == 0) {
        ngx_tcp_upstream_close(c);
        return;
    }

    if (c) {
        ngx_log_debug1(NGX_LOG_DEBUG_TCP, ctx->peer.log, 0,
                       "close tcp upstream connection: %d",
                       c->fd);
#if (NGX_TCP_SSL)

        if (c->ssl) {
            c->ssl->no_wait_shutdown = 1;
            c->ssl->no_send_shutdown = 1;

            (void) ngx_ssl_shutdown(c);
        }
#endif
        
        if (ctx->peer.check_index != (ngx_uint_t)NGX_INVALID_CHECK_INDEX) {
            ngx_tcp_check_free_peer(ctx->peer.check_index);
            ctx->peer.check_index = NGX_INVALID_CHECK_INDEX;
        }

        ngx_close_connection(c);
    }

    ngx_xmpp_upstream_connect(ctx);
}


static void
ngx_tcp_upstream_cleanup(void *data) 
{
    ngx_tcp_session_t *s = data;

    ngx_tcp_upstream_t  *u;

    ngx_log_debug1(NGX_LOG_DEBUG_TCP, s->connection->log, 0,
                   "cleanup tcp upstream session: fd: %d", s->connection->fd);

    u = s->upstream;

    if (u->resolved && u->resolved->ctx) {
        ngx_resolve_name_done(u->resolved->ctx);
    }

    ngx_tcp_upstream_finalize_session(s, u, NGX_DONE);
}

static void
ngx_tcp_upstream_keepalive_dummy_handler(ngx_event_t *ev)
{
    ngx_log_debug0(NGX_LOG_DEBUG_TCP, ev->log, 0,
                   "keepalive dummy handler");
}

void ngx_tcp_upstream_close(ngx_connection_t  *c){
	//ngx_pool_t  					*pool;
	ngx_xmpp_upstream_ctx_t			*ctx;
	
	c->destroyed = 1;
	ctx = c->data;
	
	if(ctx)
		CONN_POOL->free_peer(&ctx->peer,CONN_POOL,NGX_PEER_FAILED);
}

static void
ngx_tcp_upstream_keepalive_close_handler(ngx_event_t *ev)
{
    int                n;
    char               buf[1];
    ngx_connection_t  *c;

    ngx_log_debug0(NGX_LOG_DEBUG_TCP, ev->log, 0,
                   "keepalive close handler");

    c = ev->data;

    if (c->close) {
        goto close;
    }

    if (c->read->timedout) {
        ngx_log_debug0(NGX_LOG_DEBUG_TCP, ev->log, 0,
                       "keepalive max idle timeout");
        goto close;
    }

    n = recv(c->fd, buf, 1, MSG_PEEK);

    if (n == -1 && ngx_socket_errno == NGX_EAGAIN) {
        /* stale event */

        if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
            goto close;
        }

        return;
    }

close:


    ngx_tcp_upstream_close(c);
	

}

static void
ngx_tcp_upstream_free_keepalive_peer(ngx_tcp_session_t *s,
									 ngx_tcp_upstream_t *u,
									 ngx_uint_t state)
{

    //ngx_tcp_upstream_conn_cache_t      *item;
	int                			n;
	ngx_tcp_upstream_srv_conf_t *uscf;
    ngx_connection_t			*c;
	ngx_xmpp_upstream_ctx_t 	*ctx;
	ngx_xmpp_proxy_ctx_t		*pctx;

    /* cache valid connections */ 

    //u = kp->upstream;
	if(u->peer == NULL || u->peer->connection == NULL)return;
	
    c = u->peer->connection;
	ctx = c->data;
	uscf = u->peer->data;//ngx_tcp_get_module_srv_conf(s, ngx_tcp_upstream_module);
	
	ngx_log_debug0(NGX_LOG_DEBUG_TCP, c->log, 0, "free keepalive peer");

    if (state & NGX_PEER_FAILED
			|| c == NULL
			|| c->read->eof
			|| c->read->error
			|| c->read->timedout
			|| c->write->error
			|| c->write->timedout)
    {
        goto invalid;
    }


    

    ngx_log_debug1(NGX_LOG_DEBUG_TCP, c->log, 0, "free keepalive peer: saving connection %p", c);

    //u->peer->connection = NULL;

    if (c->read->timer_set) {
        ngx_del_timer(c->read);
    }
    if (c->write->timer_set) {
        ngx_del_timer(c->write);
    }

    if (uscf->keepalive_timeout != NGX_CONF_UNSET_MSEC &&
			uscf->keepalive_timeout != 0)
    {
        ngx_add_timer(c->read, uscf->keepalive_timeout);
    }
/*
    c->write->handler = ngx_tcp_upstream_keepalive_dummy_handler;
    c->read->handler = ngx_tcp_upstream_keepalive_close_handler;

    //c->data = item;
    c->idle = 1;
    c->log = ngx_cycle->log;
    c->read->log = ngx_cycle->log;
    c->write->log = ngx_cycle->log;
    c->pool->log = ngx_cycle->log;
*/
	pctx = ngx_tcp_get_module_ctx(s, ngx_xmpp_proxy_module);
	u_char *data = ngx_pcalloc(c->pool,XML_CM2S_CLOSE_LEN + pctx->channel_id.len);
	sprintf((char*)data,XML_CM2S_CLOSE,ctx->xml_tofrom.data,pctx->channel_id.data,pctx->channel_id.data);
	n = ngx_tcp_xmpp_upstream_send(ctx,data,ngx_strlen(data));
	if (n == NGX_ERROR) {
		//ngx_tcp_upstream_close(c);
		goto invalid;
	}

	if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
        goto invalid;
    }
	return ;
    //ngx_memcpy(&item->sockaddr, pc->sockaddr, pc->socklen);
	/*
    if (c->read->ready) {
        ngx_tcp_upstream_keepalive_close_handler(c->read);
    }
*/
invalid:

    //ngx_tcp_upstream_free_round_robin_peer(pc, kp->data, state);
	if (u->peer->free) {
        u->peer->free(u->peer, u->peer->data, 0);
    }
}

static void
ngx_tcp_upstream_finalize_session(ngx_tcp_session_t *s,
    ngx_tcp_upstream_t *u, ngx_int_t rc) 
{
	ngx_xmpp_proxy_ctx_t		*pctx;
    ngx_time_t  *tp;

    ngx_log_debug1(NGX_LOG_DEBUG_TCP, s->connection->log, 0,
                   "finalize tcp upstream session: %i", rc);

    if (u->cleanup) {
        *u->cleanup = NULL;
        u->cleanup = NULL;
    }

    if (u->state && u->state->response_sec) {
        tp = ngx_timeofday();
        u->state->response_sec = tp->sec - u->state->response_sec;
        u->state->response_msec = tp->msec - u->state->response_msec;
    }

    if (u->peer->free) {
        //u->peer->free(&u->peer, u->peer->data, 0);
		ngx_tcp_upstream_free_keepalive_peer(s, u,0);
		
    }

    if (u->peer->check_index != (ngx_uint_t)NGX_INVALID_CHECK_INDEX) {
        ngx_tcp_check_free_peer(u->peer->check_index);
        u->peer->check_index = NGX_INVALID_CHECK_INDEX;
    }

	u->peer = NULL;
	/*
    if (u->peer->connection) {

        ngx_log_debug1(NGX_LOG_DEBUG_TCP, s->connection->log, 0,
                       "close tcp upstream connection: %d",
                       u->peer->connection->fd);

        ngx_close_connection(u->peer->connection);
    }

    u->peer->connection = NULL;

    if (rc == NGX_DECLINED || rc == NGX_DONE) {
        return;
    }
*/
    //s->connection->log->action = "sending to client";
	pctx = ngx_tcp_get_module_ctx(s, ngx_xmpp_proxy_module);
	if(pctx->xmlparser)XML_ParserFree(pctx->xmlparser);
		ngx_hashtable_remove(CS_HT,pctx->channel_id.data,pctx->channel_id.len);

    //ngx_tcp_finalize_session(s);
}


ngx_tcp_upstream_srv_conf_t *
ngx_tcp_upstream_add(ngx_conf_t *cf, ngx_url_t *u, ngx_uint_t flags) 
{
    ngx_uint_t                     i;
    ngx_tcp_upstream_server_t     *us;
    ngx_tcp_upstream_srv_conf_t   *uscf, **uscfp;
    ngx_tcp_upstream_main_conf_t  *umcf;

    if (!(flags & NGX_TCP_UPSTREAM_CREATE)) {

        if (ngx_parse_url(cf->pool, u) != NGX_OK) {
            if (u->err) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "%s in upstream \"%V\"", u->err, &u->url);
            }

            return NULL;
        }
    }

    umcf = ngx_tcp_conf_get_module_main_conf(cf, ngx_tcp_upstream_module);

    uscfp = umcf->upstreams.elts;

    for (i = 0; i < umcf->upstreams.nelts; i++) {

        if (uscfp[i]->host.len != u->host.len || 
                ngx_strncasecmp(uscfp[i]->host.data,
                                u->host.data, u->host.len) != 0)
        {
            continue;
        }

        if ((flags & NGX_TCP_UPSTREAM_CREATE)
             && (uscfp[i]->flags & NGX_TCP_UPSTREAM_CREATE))
        {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "duplicate upstream \"%V\"", &u->host);
            return NULL;
        }

#if (nginx_version) >= 1003011
        if ((uscfp[i]->flags & NGX_TCP_UPSTREAM_CREATE) && !u->no_port) {
#else
        if ((uscfp[i]->flags & NGX_TCP_UPSTREAM_CREATE) && u->port) {
#endif
            ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                               "upstream \"%V\" may not have port %d",
                               &u->host, u->port);
            return NULL;
        }

#if (nginx_version) >= 1003011
        if ((flags & NGX_TCP_UPSTREAM_CREATE) && !uscfp[i]->no_port) {
#else
        if ((flags & NGX_TCP_UPSTREAM_CREATE) && uscfp[i]->port) {
#endif
            ngx_log_error(NGX_LOG_WARN, cf->log, 0,
                          "upstream \"%V\" may not have port %d in %s:%ui",
                          &u->host, uscfp[i]->port,
                          uscfp[i]->file_name, uscfp[i]->line);
            return NULL;
        }

#if (nginx_version) >= 1003011
        if (uscfp[i]->port && u->port && uscfp[i]->port != u->port) {
#else
        if (uscfp[i]->port != u->port) {
#endif
            continue;
        }

        if (uscfp[i]->default_port && u->default_port
            && uscfp[i]->default_port != u->default_port)
        {
            continue;
        }

        return uscfp[i];
    }

    uscf = ngx_pcalloc(cf->pool, sizeof(ngx_tcp_upstream_srv_conf_t));
    if (uscf == NULL) {
        return NULL;
    }

    uscf->flags = flags;
    uscf->host = u->host;
    uscf->file_name = cf->conf_file->file.name.data;
    uscf->line = cf->conf_file->line;
    uscf->port = u->port;
    uscf->default_port = u->default_port;
	
#if (nginx_version) >= 1003011
    uscf->no_port = u->no_port;
#endif
    uscf->code.status_alive = 0;

    if (u->naddrs == 1) {
        uscf->servers = ngx_array_create(cf->pool, 1,
                                         sizeof(ngx_tcp_upstream_server_t));
        if (uscf->servers == NULL) {
            return NGX_CONF_ERROR;
        }

        us = ngx_array_push(uscf->servers);
        if (us == NULL) {
            return NGX_CONF_ERROR;
        }

        ngx_memzero(us, sizeof(ngx_tcp_upstream_server_t));

        us->addrs = u->addrs;
        us->naddrs = u->naddrs;
    }

    uscfp = ngx_array_push(&umcf->upstreams);
    if (uscfp == NULL) {
        return NULL;
    }

    *uscfp = uscf;
	

    return uscf;
}


static char *
ngx_tcp_upstream(ngx_conf_t *cf, ngx_command_t *cmd, void *dummy) 
{
    char                          *rv;
    void                          *mconf;
    ngx_str_t                     *value;
    ngx_url_t                      u;
    ngx_uint_t                     m;
    ngx_conf_t                     pcf;
    ngx_tcp_module_t              *module;
    ngx_tcp_conf_ctx_t            *ctx, *tcp_ctx;
    ngx_tcp_upstream_srv_conf_t   *uscf;

    ngx_memzero(&u, sizeof(ngx_url_t));

    value = cf->args->elts;
    u.host = value[1];
    u.no_resolve = 1;
    u.no_port = 1;

    uscf = ngx_tcp_upstream_add(cf, &u, 
                                NGX_TCP_UPSTREAM_CREATE
                               |NGX_TCP_UPSTREAM_WEIGHT
                               |NGX_TCP_UPSTREAM_MAX_FAILS
                               |NGX_TCP_UPSTREAM_FAIL_TIMEOUT
                               |NGX_TCP_UPSTREAM_MAX_BUSY
                               |NGX_TCP_UPSTREAM_DOWN
                               |NGX_TCP_UPSTREAM_BACKUP);
    if (uscf == NULL) {
        return NGX_CONF_ERROR;
    }
	uscf->keepalive_timeout = NGX_CONF_UNSET_MSEC;
	uscf->buffer_size=4096;
	
    ctx = ngx_pcalloc(cf->pool, sizeof(ngx_tcp_conf_ctx_t));
    if (ctx == NULL) {
        return NGX_CONF_ERROR;
    }

    tcp_ctx = cf->ctx;
    ctx->main_conf = tcp_ctx->main_conf;

    /* the upstream{}'s srv_conf */

    ctx->srv_conf = ngx_pcalloc(cf->pool, sizeof(void *) * ngx_tcp_max_module);
    if (ctx->srv_conf == NULL) {
        return NGX_CONF_ERROR;
    }

    ctx->srv_conf[ngx_tcp_upstream_module.ctx_index] = uscf;

    uscf->srv_conf = ctx->srv_conf;


    for (m = 0; ngx_modules[m]; m++) {
        if (ngx_modules[m]->type != NGX_TCP_MODULE) {
            continue;
        }

        module = ngx_modules[m]->ctx;

        if (module->create_srv_conf) {
            mconf = module->create_srv_conf(cf);
            if (mconf == NULL) {
                return NGX_CONF_ERROR;
            }

            ctx->srv_conf[ngx_modules[m]->ctx_index] = mconf;
        }

    }

    /* parse inside upstream{} */

    pcf = *cf;
    cf->ctx = ctx;
    cf->cmd_type = NGX_TCP_UPS_CONF;

    rv = ngx_conf_parse(cf, NULL);

    *cf = pcf;

    if (rv != NGX_CONF_OK) {
        return rv;
    }

    if (uscf->servers == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "no servers are inside upstream");
        return NGX_CONF_ERROR;
    }
	
	
	CONN_POOL = ngx_tcp_connection_pool_init(cf->pool,ctx);
	if (CONN_POOL == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "no servers are inside upstream");
        return NGX_CONF_ERROR;
    }

    return rv;
}


static char *
ngx_tcp_upstream_server(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) 
{
    ngx_tcp_upstream_srv_conf_t  *uscf = conf;

    time_t                       fail_timeout;
    ngx_str_t                   *value, s;
    ngx_url_t                    u;
    ngx_int_t                    weight, max_fails, max_busy;
    ngx_uint_t                   i;
    ngx_tcp_upstream_server_t   *us;

    if (uscf->servers == NULL) {
        uscf->servers = ngx_array_create(cf->pool, 4,
                                         sizeof(ngx_tcp_upstream_server_t));
        if (uscf->servers == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    us = ngx_array_push(uscf->servers);
    if (us == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(us, sizeof(ngx_tcp_upstream_server_t));

    value = cf->args->elts;

    ngx_memzero(&u, sizeof(ngx_url_t));

    u.url = value[1];
    u.default_port = 80;

    if (ngx_parse_url(cf->pool, &u) != NGX_OK) {
        if (u.err) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "%s in upstream \"%V\"", u.err, &u.url);
        }

        return NGX_CONF_ERROR;
    }

    weight = 1;
    max_fails = 1;
    max_busy = (ngx_uint_t)-1;
    fail_timeout = 10;

    for (i = 2; i < cf->args->nelts; i++) {

        if (ngx_strncmp(value[i].data, "weight=", 7) == 0) {

            if (!(uscf->flags & NGX_TCP_UPSTREAM_WEIGHT)) {
                goto invalid;
            }

            weight = ngx_atoi(&value[i].data[7], value[i].len - 7);

            if (weight == NGX_ERROR || weight == 0) {
                goto invalid;
            }

            continue;
        }

        if (ngx_strncmp(value[i].data, "max_fails=", 10) == 0) {

            if (!(uscf->flags & NGX_TCP_UPSTREAM_MAX_FAILS)) {
                goto invalid;
            }

            max_fails = ngx_atoi(&value[i].data[10], value[i].len - 10);

            if (max_fails == NGX_ERROR) {
                goto invalid;
            }

            continue;
        }

        if (ngx_strncmp(value[i].data, "max_busy=", 9) == 0) {

            if (!(uscf->flags & NGX_TCP_UPSTREAM_MAX_BUSY)) {
                goto invalid;
            }

            max_busy = ngx_atoi(&value[i].data[9], value[i].len - 9);

            if (max_busy == NGX_ERROR) {
                goto invalid;
            }

            continue;
        }

        if (ngx_strncmp(value[i].data, "fail_timeout=", 13) == 0) {

            if (!(uscf->flags & NGX_TCP_UPSTREAM_FAIL_TIMEOUT)) {
                goto invalid;
            }

            s.len = value[i].len - 13;
            s.data = &value[i].data[13];

            fail_timeout = ngx_parse_time(&s, 1);

            if (fail_timeout == NGX_ERROR) {
                goto invalid;
            }

            continue;
        }

        if (ngx_strncmp(value[i].data, "backup", 6) == 0) {

            if (!(uscf->flags & NGX_TCP_UPSTREAM_BACKUP)) {
                goto invalid;
            }

            us->backup = 1;

            continue;
        }

        if (ngx_strncmp(value[i].data, "down", 4) == 0) {

            if (!(uscf->flags & NGX_TCP_UPSTREAM_DOWN)) {
                goto invalid;
            }

            us->down = 1;

            continue;
        }

        goto invalid;
    }

    us->addrs = u.addrs;
    us->naddrs = u.naddrs;
    us->weight = weight;
    us->max_fails = max_fails;
    us->max_busy = max_busy;
    us->fail_timeout = fail_timeout;

    return NGX_CONF_OK;

invalid:

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "invalid parameter \"%V\"", &value[i]);

    return NGX_CONF_ERROR;
}


static char *
ngx_tcp_upstream_check(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) 
{
    ngx_tcp_upstream_srv_conf_t  *uscf = conf;

    ngx_str_t   *value, s;
    ngx_uint_t   i, rise, fall;
    ngx_msec_t   interval, timeout;

    /*set default*/
    rise = 2;
    fall = 5;
    interval = 30000;
    timeout = 1000;

    value = cf->args->elts;

    for (i = 1; i < cf->args->nelts; i++) {

        if (ngx_strncmp(value[i].data, "type=", 5) == 0) {
            s.len = value[i].len - 5;
            s.data = value[i].data + 5;

            uscf->check_type_conf = ngx_tcp_get_check_type_conf(&s);

            if ( uscf->check_type_conf == NULL) {
                goto invalid_check_parameter;
            }

            continue;
        }

        if (ngx_strncmp(value[i].data, "interval=", 9) == 0) {
            s.len = value[i].len - 9;
            s.data = value[i].data + 9;

            interval = ngx_atoi(s.data, s.len);
            if (interval == (ngx_msec_t) NGX_ERROR) {
                goto invalid_check_parameter;
            }

            continue;
        }

        if (ngx_strncmp(value[i].data, "timeout=", 8) == 0) {
            s.len = value[i].len - 8;
            s.data = value[i].data + 8;

            timeout = ngx_atoi(s.data, s.len);
            if (timeout == (ngx_msec_t) NGX_ERROR) {
                goto invalid_check_parameter;
            }

            continue;
        }

        if (ngx_strncmp(value[i].data, "rise=", 5) == 0) {
            s.len = value[i].len - 5;
            s.data = value[i].data + 5;

            rise = ngx_atoi(s.data, s.len);
            if (rise == (ngx_uint_t) NGX_ERROR) {
                goto invalid_check_parameter;
            }

            continue;
        }

        if (ngx_strncmp(value[i].data, "fall=", 5) == 0) {
            s.len = value[i].len - 5;
            s.data = value[i].data + 5;

            fall = ngx_atoi(s.data, s.len);
            if (fall == (ngx_uint_t) NGX_ERROR) {
                goto invalid_check_parameter;
            }

            continue;
        }

        goto invalid_check_parameter;
    }

    uscf->check_interval = interval;
    uscf->check_timeout = timeout;
    uscf->fall_count = fall;
    uscf->rise_count = rise;

    if (uscf->check_type_conf == NULL) {
        s.len = sizeof("tcp") - 1;
        s.data =(u_char *) "tcp";

        uscf->check_type_conf = ngx_tcp_get_check_type_conf(&s);
    }

    return NGX_CONF_OK;

invalid_check_parameter:

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "invalid parameter \"%V\"", &value[i]);

    return NGX_CONF_ERROR;
}


static void *
ngx_tcp_upstream_create_main_conf(ngx_conf_t *cf) 
{
    ngx_tcp_upstream_main_conf_t  *umcf;

    umcf = ngx_pcalloc(cf->pool, sizeof(ngx_tcp_upstream_main_conf_t));
    if (umcf == NULL) {
        return NULL;
    }

    umcf->peers_conf = ngx_pcalloc(cf->pool,
                                   sizeof(ngx_tcp_check_peers_conf_t));
    if (umcf->peers_conf == NULL) {
        return NULL;
    }

    if (ngx_array_init(&umcf->upstreams, cf->pool, 4,
                       sizeof(ngx_tcp_upstream_srv_conf_t *)) != NGX_OK)
    {
        return NULL;
    }

    if (ngx_array_init(&umcf->peers_conf->peers, cf->pool, 16,
                       sizeof(ngx_tcp_check_peer_conf_t)) != NGX_OK)
    {
        return NULL;
    }

    return umcf;
}


static char *
ngx_tcp_upstream_init_main_conf(ngx_conf_t *cf, void *conf) 
{
    ngx_tcp_upstream_main_conf_t   *umcf = conf;

    ngx_uint_t                      i;
    ngx_tcp_upstream_init_pt        init;
    ngx_tcp_upstream_srv_conf_t   **uscfp;

    uscfp = umcf->upstreams.elts;

    if (ngx_tcp_upstream_init_main_check_conf(cf, conf) != NGX_OK) {
            return NGX_CONF_ERROR;
    }

    for (i = 0; i < umcf->upstreams.nelts; i++) {

        init = uscfp[i]->peer.init_upstream ? uscfp[i]->peer.init_upstream:
                                              ngx_tcp_upstream_init_round_robin;

        if (init(cf, uscfp[i]) != NGX_OK) {
            return NGX_CONF_ERROR;
        }
    }

    return NGX_CONF_OK;
}

static char *
ngx_tcp_upstream_connections(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_tcp_upstream_srv_conf_t            *uscf;

    ngx_int_t    n;
    ngx_str_t   *value;
    ngx_uint_t   i;

    uscf = ngx_tcp_conf_get_module_srv_conf(cf, ngx_tcp_upstream_module);

    /* read options */

    value = cf->args->elts;

    n = ngx_atoi(value[1].data, value[1].len);

    if (n == NGX_ERROR || n == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid value \"%V\" in \"%V\" directive",
                           &value[1], &cmd->name);
        return NGX_CONF_ERROR;
    }

    uscf->max_cached = n;

    for (i = 2; i < cf->args->nelts; i++) {

        if (ngx_strcmp(value[i].data, "single") == 0) {
            ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                               "the \"single\" parameter is deprecated");
            continue;
        }

        goto invalid;
    }

    return NGX_CONF_OK;

invalid:

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "invalid parameter \"%V\"", &value[i]);

    return NGX_CONF_ERROR;
}


static char *
ngx_tcp_upstream_keepalive_timeout(ngx_conf_t *cf, ngx_command_t *cmd,
								   void *conf)
{
    ngx_tcp_upstream_srv_conf_t            *uscf;

    ngx_str_t   *value;
    ngx_msec_t   timeout;

    uscf = ngx_tcp_conf_get_module_srv_conf(cf, ngx_tcp_upstream_module);


    if (uscf->keepalive_timeout != NGX_CONF_UNSET_MSEC) {
        return "is duplicate";
    }

    value = cf->args->elts;

    timeout = ngx_parse_time(&value[1], 0);
    if (timeout == (ngx_msec_t) NGX_ERROR) {
        return "invalid value";
    }

    uscf->keepalive_timeout = timeout;

    return NGX_CONF_OK;
}

static char *
ngx_tcp_upstream_buffer_size(ngx_conf_t *cf, ngx_command_t *cmd,
								   void *conf)
{
    ngx_tcp_upstream_srv_conf_t            *uscf;

    ngx_str_t   *value;
    ngx_msec_t   buffer_size;

    uscf = ngx_tcp_conf_get_module_srv_conf(cf, ngx_tcp_upstream_module);

    value = cf->args->elts;

    buffer_size = ngx_atoi(value[1].data, value[1].len);

    if (buffer_size == NGX_ERROR || buffer_size == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid value \"%V\" in \"%V\" directive",
                           &value[1], &cmd->name);
        return NGX_CONF_ERROR;
    }

    uscf->buffer_size = buffer_size;

    return NGX_CONF_OK;
}
