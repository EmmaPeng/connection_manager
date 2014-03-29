
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_sha1.h>
#include <ngx_tcp.h>
#include <expat.h>
#include <ngx_xmpp_connection_pool.h>
#include <ngx_tcp_xmpp.h>

typedef struct {
    ngx_queue_t                        queue;
    ngx_event_t 						*ev;
} ngx_xmpp_proxy_event_cache_t;

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
ngx_tcp_upstream_keepalive_dummy_handler(ngx_event_t *ev)
{
    ngx_log_debug0(NGX_LOG_DEBUG_TCP, ev->log, 0,
                   "keepalive dummy handler");
}

void
ngx_xmpp_proxy_event_add(ngx_xmpp_upstream_ctx_t *ctx,ngx_event_t *ev){
	ngx_xmpp_proxy_event_cache_t	*item;
	item = ngx_pcalloc(ctx->pool, sizeof(ngx_xmpp_proxy_event_cache_t));
	item->ev = ev;
	ngx_queue_insert_tail(&ctx->queue, &item->queue);
}

void
ngx_xmpp_proxy_event_delete(ngx_xmpp_upstream_ctx_t *ctx,ngx_event_t *ev){
	ngx_queue_t       				*q, *cache;
	ngx_xmpp_proxy_event_cache_t	*item;
    ngx_log_debug0(NGX_LOG_DEBUG_TCP, ev->log, 0,
                   "ngx_xmpp_proxy_event_delete");
	cache = &ctx->queue;

    for (q = ngx_queue_head(cache);
			q != ngx_queue_sentinel(cache);
			q = ngx_queue_next(q))
    {
        item = ngx_queue_data(q, ngx_xmpp_proxy_event_cache_t, queue);
		if(ev == item->ev){
			ev = item->ev;
			ngx_xmpp_proxy_handler(ev);
			
			ngx_queue_remove(q);
			ngx_pfree(ctx->pool,item);
			
			return;
		}
    }
}
void
ngx_xmpp_upstream_connect_finished(ngx_xmpp_upstream_ctx_t *ctx)
{
	ngx_queue_t       				*q, *cache, *root;
	ngx_xmpp_proxy_event_cache_t	*item;
	ngx_event_t 					*ev;
    ngx_log_debug0(NGX_LOG_DEBUG_TCP, ctx->peer.log, 0,
                   "ngx_xmpp_upstream_connect_finished");
	ctx->state = XMPP_CM_READY;
	root = &ctx->queue;
	q = ngx_queue_head(root);
    while (q != ngx_queue_sentinel(root))
    {
        item = ngx_queue_data(q, ngx_xmpp_proxy_event_cache_t, queue);
        ev = item->ev;
		ngx_xmpp_proxy_handler(ev);
		cache = ngx_queue_next(q);
		ngx_queue_remove(q);
		ngx_pfree(ctx->pool,item);
		q = cache;
    }
}

ngx_int_t
ngx_tcp_connection_pool_get(ngx_peer_connection_t *_pc, void *data)
{
    //u_char                         	pc_addr[32] = {'\0'};
    ngx_uint_t                     	rc;
    ngx_tcp_connection_pool_t     	*p;
    ngx_tcp_connection_pool_elt_t 	*item;
	ngx_xmpp_upstream_ctx_t 		*ctx;
	//ngx_tcp_upstream_srv_conf_t    	*uscf;
	ngx_peer_connection_t			*peer,*pc,**_pcs = (ngx_peer_connection_t**)_pc;
	
    p = data;
	pc = *(_pcs);
	
	
	//ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0,"get keepalive peer");
	
	/* ask balancer */
	rc = ngx_tcp_upstream_get_round_robin_peer(pc, pc->data);

    if (rc != NGX_OK) {
        return rc;
    }
	
	
	item=ngx_hashtable_get(p->hashtable,(u_char*)pc->sockaddr,pc->socklen);
		
	if(item->last_cached >= p->max_cached)
		item->last_cached=0;
	
	ctx = item->cached[item->last_cached];
	
	if(ctx == NULL ){
		
		ctx = ngx_pcalloc(p->pool,sizeof(ngx_xmpp_upstream_ctx_t));
		peer = ngx_pcalloc(p->pool,sizeof(ngx_peer_connection_t));
		if (ctx == NULL || peer == NULL) {
            return NGX_ERROR;
        }
		//problem.....
		ctx->conf = p->data;
		ctx->state = XMPP_CM_UNUSE;

		ctx->channel_id.data = ngx_pcalloc(p->pool,XMPP_MAX_CHN_LEN);
		ctx->xml_streamid.data = ngx_pcalloc(p->pool,XMPP_STREAM_ID_LEN);
		
		ctx->wbuffer = ngx_create_temp_buf(p->pool, p->uscf->buffer_size);
		if (ctx->wbuffer == NULL || ctx->channel_id.data == NULL) {
			ngx_log_error(NGX_LOG_DEBUG, pc->log, 0, "Couldn't allocate memory for 'channel_id|wbuffer'");
            return NGX_ERROR;
		}
		
		// set xml_tofrom  =>  server_name/index
		if(item->last_cached<10){
			ctx->xml_tofrom.len = p->uscf->server_name.len+2;
		}else if(item->last_cached<100){
			ctx->xml_tofrom.len = p->uscf->server_name.len+3;
		}else{
			ctx->xml_tofrom.len = p->uscf->server_name.len+4;
		}
		ctx->xml_tofrom.data = ngx_pcalloc(p->pool,ctx->xml_tofrom.len);
		sprintf(ctx->xml_tofrom.data,"%s/%lu",p->uscf->server_name.data,item->last_cached);
		ngx_queue_init(&ctx->queue);
		ctx->peer.log = ngx_cycle->log;
		ctx->pool = ngx_create_pool(256,ngx_cycle->log);
		item->cached[item->last_cached]=ctx;
	}
	
	//uscf = ctx->conf->upstream;
	
	peer = &ctx->peer;
	
	if(peer->connection == NULL){
		ngx_event_get_peer_pt get = pc->get;
		pc->get=NULL;
		rc = ngx_event_connect_peer(pc);
		pc->get=get;
		
		if (rc != NGX_OK && rc != NGX_AGAIN) {
			if(pc->connection == NULL)return NGX_ERROR;
			pc->connection->write->handler = ngx_tcp_upstream_keepalive_dummy_handler;
			pc->connection->read->handler = ngx_tcp_upstream_keepalive_close_handler;
			pc->connection = NULL;
			return NGX_ERROR;
		}
		pc->connection->data = ctx;
		
		pc->connection->buffer = ngx_create_temp_buf(ctx->pool, p->uscf->buffer_size);
		ctx->xmlparser = XML_ParserCreate(NULL);
		if (pc->connection->buffer == NULL || ctx->xmlparser == NULL) {
			ngx_log_error(NGX_LOG_DEBUG, pc->log, 0, "Couldn't allocate memory for 'xmlparser|wbuffer'");
            goto invalid;
		}
		ctx->xml_depth=0;
		XML_SetUserData(ctx->xmlparser, pc->connection);
		XML_SetElementHandler(ctx->xmlparser, ngx_xmpp_upstream_xmlstart, ngx_xmpp_upstream_xmlend);
		
		//char *data = ngx_pcalloc(c->pool,XML_CM2S_CONNECTION_LEN + s->connection->channel_id.len);
		//sprintf(data,XML_CM2S_CONNECTION,s->connection->channel_id.data);
		
		
		ctx->cache_slot = item->last_cached;
		ctx->cache_sockaddr = pc->sockaddr;
		ctx->cache_socklen = pc->socklen;
		
		
		peer->get = pc->get;
		peer->free = pc->free;
		peer->tries = pc->tries;
		peer->check_index = pc->check_index;
		peer->name = pc->name;
		peer->connection = pc->connection;
		peer->sockaddr = pc->sockaddr;
		peer->socklen = pc->socklen;
		peer->data = pc->data;
#if (NGX_SSL)
		peer->set_session = pc->set_session;
		peer->save_session = pc->save_session;
#endif
		peer->local = pc->local;
		peer->connection->pool = ctx->pool;
		peer->log = ngx_cycle->log;
		peer->connection->idle = 0;
		peer->connection->log = ngx_cycle->log;
		peer->connection->read->log = ngx_cycle->log;
		peer->connection->write->log = ngx_cycle->log;
		
		sprintf(ctx->wbuffer->last, XML_CM2S_CONNECTION, (char*)ctx->xml_tofrom.data);
		ctx->wbuffer->last += XML_CM2S_CONNECTION_LEN + ctx->xml_tofrom.len - 2;
		rc = ngx_tcp_xmpp_upstream_send(ctx,NULL,0);
		if (rc == NGX_ERROR) {
			goto invalid;
		}
		ctx->state = XMPP_CM_CONNECTION;
	}

	ngx_log_debug1(NGX_LOG_DEBUG_TCP, pc->log, 0, "get keepalive peer: using connection %p", peer->connection);
	
	
	//c->pool->log = pc->log;
	

	//if (peer->connection->read->timer_set) {
		//ngx_del_timer(peer->connection->read);
	//}
	item->last_cached++;
	ctx->destroyed=0;
	peer->cached = 1;
	
	*_pcs = peer;

	return rc;
	
invalid:
	XML_ParserFree(ctx->xmlparser);
	pc->connection->write->handler = ngx_tcp_upstream_keepalive_dummy_handler;
	pc->connection->read->handler = ngx_tcp_upstream_keepalive_close_handler;
	pc->connection->pool = NULL;
	ngx_close_accepted_connection(pc->connection);
	pc->connection = NULL;
	ngx_reset_pool(ctx->pool);
	return NGX_ERROR;
}


void
ngx_tcp_connection_pool_free(ngx_peer_connection_t *pc,
							  void *data, ngx_uint_t state)
{
    ngx_tcp_connection_pool_t     *p = data;
    ngx_tcp_connection_pool_elt_t *item;
	ngx_xmpp_upstream_ctx_t			*ctx;

    ngx_connection_t  *c;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0, "free keepalive peer");

	c = pc->connection;
	ctx = c->data;
	
	
    /* remember failed state - peer.free() may be called more than once */

    if (state & NGX_PEER_FAILED) {
        p->failed = 1;
    }

    /* cache valid connections */

    if (p->failed
			|| (c->read->eof && (c->read->error || c->write->error))
			|| c->read->timedout
			|| c->write->timedout)
    {
		item=ngx_hashtable_get(p->hashtable,pc->sockaddr,pc->socklen);
		pc->connection = NULL;
		if(ctx->xmlparser)
			XML_ParserFree(ctx->xmlparser);
		
		ngx_reset_pool(c->pool);
		c->pool=NULL;
		ngx_close_connection(c);
		if(item->cached[ctx->cache_slot] != ctx){
			ngx_pfree(p->pool,pc);
			ngx_pfree(p->pool,ctx);
		}
		ctx->destroyed=1;
		ctx->state = XMPP_CM_UNUSE;
		ctx->wbuffer->pos = ctx->wbuffer->start;
		ctx->wbuffer->last = ctx->wbuffer->start;
		/*
		ngx_tcp_upstream_rr_peer_data_t *rrp = pc->data;
		//memset(rrp,0,sizeof(ngx_tcp_upstream_rr_peer_data_t));
		memset(pc,0,sizeof(ngx_peer_connection_t));
		pc->data = rrp;
		
		pc->log_error = NGX_ERROR_ERR;
		pc->get = ngx_tcp_upstream_get_round_robin_peer;
		pc->free = ngx_tcp_upstream_free_round_robin_peer;
		pc->tries = rrp->peers->number;
		pc->check_index = NGX_INVALID_CHECK_INDEX;
		pc->name = NULL;
#if (NGX_TCP_SSL)
		pc->set_session =
			ngx_tcp_upstream_set_round_robin_peer_session;
		pc->save_session =
			ngx_tcp_upstream_save_round_robin_peer_session;
#endif
		*/
        return;
    }
	
	if (c->read->timer_set) {
	ngx_del_timer(c->read);
	}

	if (c->write->timer_set) {
	ngx_del_timer(c->write);
	}
	

    if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
        return;
    }

}


ngx_tcp_connection_pool_t *
ngx_tcp_connection_pool_init(ngx_pool_t *pool, ngx_tcp_conf_ctx_t *cfctx)
{
    ngx_tcp_connection_pool_t   *conn_pool;
	ngx_tcp_upstream_server_t	*server;
	ngx_uint_t 					server_count;
	
    conn_pool = ngx_pcalloc(pool, sizeof(ngx_tcp_connection_pool_t));
    if (conn_pool == NULL) {
        return NULL;
    }
	conn_pool->pool = pool;

	
	conn_pool->uscf = cfctx->srv_conf[ngx_tcp_upstream_module.ctx_index];//ngx_tcp_conf_get_module_srv_conf(cf, ngx_tcp_upstream_module);
	
    conn_pool->bucket_count = 1000;
    conn_pool->max_cached = conn_pool->uscf->max_cached;
	conn_pool->get_peer = ngx_tcp_connection_pool_get;
	conn_pool->free_peer = ngx_tcp_connection_pool_free;

	conn_pool->hashtable = ngx_hashtable_create(pool,conn_pool->bucket_count);
	if (conn_pool->hashtable == NULL) {
        return NULL;
    }
	ngx_peer_connection_t **conns;
	ngx_tcp_connection_pool_elt_t *cache;
	
	server = conn_pool->uscf->servers->elts;
	server_count = conn_pool->uscf->servers->nelts;
	//char *addr;
	for (int i = 0; i < server_count; i++) {
		
		cache = ngx_pcalloc(pool,
							sizeof(ngx_tcp_connection_pool_elt_t));
		cache->last_cached=0;
		conns = ngx_pcalloc(pool,
							sizeof(ngx_peer_connection_t*) * conn_pool->max_cached);
		cache->cached=conns;
		//addr=(u_char*)server[i].addrs->sockaddr;
		cache->socklen=server[i].addrs->socklen;//server[i].naddrs;
		
		//printf("==========%s,%d,%d\n",addr,cache->socklen,server[i].naddrs);
		ngx_copy(cache->sockaddr,(u_char*)server[i].addrs->sockaddr,cache->socklen);
		
		ngx_hashtable_set(&conn_pool->hashtable,cache->sockaddr,cache->socklen,cache);
    }
	
	return conn_pool;
}
