

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_tcp.h>
#include <ngx_tcp_xmpp.h>




typedef struct ngx_xmpp_proxy_conf_s {
    ngx_tcp_upstream_conf_t   upstream;

    ngx_str_t                 url;
    size_t                    buffer_size;
} ngx_xmpp_proxy_conf_t;


static void ngx_xmpp_proxy_init_session(ngx_tcp_session_t *s); 
static  void ngx_xmpp_proxy_init_upstream(ngx_connection_t *c, 
    ngx_tcp_session_t *s);
static void ngx_tcp_upstream_init_proxy_handler(ngx_tcp_session_t *s, 
    ngx_tcp_upstream_t *u);
static char *ngx_xmpp_proxy_pass(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static void ngx_xmpp_proxy_dummy_read_handler(ngx_event_t *ev);
static void ngx_xmpp_proxy_dummy_write_handler(ngx_event_t *ev);
static void *ngx_xmpp_proxy_create_conf(ngx_conf_t *cf);
static char *ngx_xmpp_proxy_merge_conf(ngx_conf_t *cf, void *parent,
    void *child);

ngx_hashtable_t		*CS_HT;

static ngx_tcp_protocol_t  ngx_tcp_xmpp_protocol = {

    ngx_string("test_xmpp"),
    { 0, 0, 0, 0 },
    NGX_TCP_GENERIC_PROTOCOL,
    ngx_xmpp_proxy_init_session,
    NULL,
    NULL,
    ngx_string("500 Internal server error" CRLF)

};


static ngx_command_t  ngx_xmpp_proxy_commands[] = {

    { ngx_string("test_pass"),
      NGX_TCP_MAIN_CONF|NGX_TCP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_xmpp_proxy_pass,
      NGX_TCP_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("test_buffer"),
      NGX_TCP_MAIN_CONF|NGX_TCP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_TCP_SRV_CONF_OFFSET,
      offsetof(ngx_xmpp_proxy_conf_t, buffer_size),
      NULL },

    { ngx_string("test_connect_timeout"),
      NGX_TCP_MAIN_CONF|NGX_TCP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_TCP_SRV_CONF_OFFSET,
      offsetof(ngx_xmpp_proxy_conf_t, upstream.connect_timeout),
      NULL },

    { ngx_string("test_read_timeout"),
      NGX_TCP_MAIN_CONF|NGX_TCP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_TCP_SRV_CONF_OFFSET,
      offsetof(ngx_xmpp_proxy_conf_t, upstream.read_timeout),
      NULL },

    { ngx_string("test_send_timeout"),
      NGX_TCP_MAIN_CONF|NGX_TCP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_TCP_SRV_CONF_OFFSET,
      offsetof(ngx_xmpp_proxy_conf_t, upstream.send_timeout),
      NULL },

    ngx_null_command
};


static ngx_tcp_module_t  ngx_xmpp_proxy_module_ctx = {
    &ngx_tcp_xmpp_protocol,             /* protocol */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    ngx_xmpp_proxy_create_conf,             /* create server configuration */
    ngx_xmpp_proxy_merge_conf               /* merge server configuration */
};


ngx_module_t  ngx_test_proxy_module = {
    NGX_MODULE_V1,
    &ngx_xmpp_proxy_module_ctx,             /* module context */
    ngx_xmpp_proxy_commands,                /* module directives */
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


static void 
ngx_xmpp_proxy_init_session(ngx_tcp_session_t *s) 
{
    ngx_connection_t         *c;
    ngx_xmpp_proxy_conf_t     *pcf;
    ngx_tcp_core_srv_conf_t  *cscf;
	ngx_xmpp_proxy_ctx_t      *ctx;

    c = s->connection;

    ngx_log_debug0(NGX_LOG_DEBUG_TCP, c->log, 0, "xmpp proxy init session");

    cscf = ngx_tcp_get_module_srv_conf(s, ngx_tcp_core_module);

    pcf = ngx_tcp_get_module_srv_conf(s, ngx_xmpp_proxy_module);
	
	ctx = ngx_pcalloc(s->connection->pool, sizeof(ngx_xmpp_proxy_ctx_t));
    if (ctx == NULL) {
        ngx_tcp_finalize_session(s);
        return;
    }

	//ctx->buffer = ngx_create_temp_buf(s->connection->pool, pcf->buffer_size);
    //if (p->buffer == NULL) {
    //    ngx_tcp_finalize_session(s);
    //    return;
    //}

    ngx_tcp_set_ctx(s, ctx, ngx_xmpp_proxy_module);

	ctx->xml_state = XMPP_SESSION_UNUSE;
    s->buffer = ngx_create_temp_buf(s->connection->pool, pcf->buffer_size);
    if (s->buffer == NULL) {
		ngx_log_error(NGX_LOG_DEBUG, c->log, 0, "Couldn't allocate memory for buffer");
        ngx_tcp_finalize_session(s);
        return;
    }
	
	ctx->wbuffer = ngx_create_temp_buf(s->connection->pool, pcf->buffer_size);
    if (ctx->wbuffer == NULL) {
		ngx_log_error(NGX_LOG_DEBUG, c->log, 0, "Couldn't allocate memory for wbuffer");
        ngx_tcp_finalize_session(s);
        return;
    }
	
	ctx->channel_id.data = (u_char*)ngx_pcalloc(s->connection->pool,XMPP_MAX_CHN_LEN);
	ngx_time_update();
	ngx_sprintf(ctx->channel_id.data,"%d-%d",ngx_time(),s->connection->fd);
	ctx->channel_id.len=ngx_strlen(ctx->channel_id.data);
	
	
	ngx_hashtable_set(&CS_HT,ctx->channel_id.data,ctx->channel_id.len,s);
	
	ctx->xmlparser = XML_ParserCreate(NULL);
	if (ctx->xmlparser == NULL) {
		ngx_log_error(NGX_LOG_DEBUG, c->log, 0, "Couldn't allocate memory for parser");
		ngx_tcp_finalize_session(s);
		return;
	}
	ctx->xml_depth=0;
	XML_SetUserData(ctx->xmlparser, s);
	XML_SetElementHandler(ctx->xmlparser, ngx_xmpp_proxy_xmlstart, ngx_xmpp_proxy_xmlend);

    s->out.len = 0;

    c->write->handler = ngx_xmpp_proxy_dummy_write_handler;
    c->read->handler = ngx_xmpp_proxy_dummy_read_handler;

    ngx_add_timer(c->read, cscf->timeout);

    ngx_xmpp_proxy_init_upstream(c, s);

    return;
}


static void
ngx_xmpp_proxy_dummy_write_handler(ngx_event_t *wev) 
{
    ngx_connection_t    *c;
    ngx_tcp_session_t   *s;

    c = wev->data;
    s = c->data;

    ngx_log_debug1(NGX_LOG_DEBUG_TCP, wev->log, 0,
                   "xmpp proxy dummy write handler: %d", c->fd);

    if (ngx_handle_write_event(wev, 0) != NGX_OK) {
        ngx_tcp_finalize_session(s);
    }
}


static void
ngx_xmpp_proxy_dummy_read_handler(ngx_event_t *rev) 
{
    ngx_connection_t    *c;
    ngx_tcp_session_t   *s;

    c = rev->data;
    s = c->data;

    ngx_log_debug1(NGX_LOG_DEBUG_TCP, rev->log, 0,
                   "xmpp proxy dummy read handler: %d", c->fd);

    if (ngx_handle_read_event(rev, 0) != NGX_OK) {
        ngx_tcp_finalize_session(s);
    }
}

static  void
ngx_xmpp_proxy_init_upstream(ngx_connection_t *c, ngx_tcp_session_t *s)
{
    ngx_tcp_upstream_t       *u;
    ngx_xmpp_proxy_conf_t     *pcf;

    s->connection->log->action = "ngx_xmpp_proxy_init_upstream";

    pcf = ngx_tcp_get_module_srv_conf(s, ngx_xmpp_proxy_module);
    if (pcf->upstream.upstream == NULL) {
        ngx_tcp_finalize_session(s);
        return;
    }

    

	//s->upstream=UPSTREAM;
	//if(UPSTREAM == NULL){
		if (ngx_tcp_upstream_create(s) != NGX_OK) {
			ngx_tcp_finalize_session(s);
			return;
		}
		//UPSTREAM=s->upstream;
	//}
	
    u = s->upstream;

    u->conf = &pcf->upstream;

    u->write_event_handler = ngx_tcp_upstream_init_proxy_handler;
    u->read_event_handler = ngx_tcp_upstream_init_proxy_handler;

    ngx_tcp_upstream_init(s);
    return;
}


static void 
ngx_tcp_upstream_init_proxy_handler(ngx_tcp_session_t *s, ngx_tcp_upstream_t *u)
{
    ngx_connection_t         *c;
    ngx_xmpp_proxy_ctx_t      *pctx;
    ngx_xmpp_proxy_conf_t     *pcf;

    c = s->connection;
    c->log->action = "ngx_tcp_upstream_init_proxy_handler";

    ngx_log_debug0(NGX_LOG_DEBUG_TCP, s->connection->log, 0,
                   "xmpp proxy upstream init proxy");

    pcf = ngx_tcp_get_module_srv_conf(s, ngx_xmpp_proxy_module);

    pctx = ngx_tcp_get_module_ctx(s, ngx_xmpp_proxy_module);

    if (pcf == NULL || pctx == NULL) {
        ngx_tcp_finalize_session(s);
        return;
    }

    /*pctx->upstream = &s->upstream->peer;

    c = pctx->upstream->connection;
    if (c->read->timedout || c->write->timedout) {
        ngx_tcp_upstream_next(s, u, NGX_TCP_UPSTREAM_FT_TIMEOUT);
        return;
    }

    if (ngx_tcp_upstream_check_broken_connection(s) != NGX_OK){
        ngx_tcp_upstream_next(s, u, NGX_TCP_UPSTREAM_FT_ERROR);
        return;
    }

 

    c->read->handler = ngx_xmpp_upstream_handler;
    c->write->handler = ngx_xmpp_upstream_handler;

    ngx_add_timer(c->read, pcf->upstream.read_timeout);
    ngx_add_timer(c->write, pcf->upstream.send_timeout);
*/
	s->connection->read->handler = ngx_xmpp_proxy_handler;
    s->connection->write->handler = ngx_xmpp_proxy_handler;
	s->upstream->read_event_handler = NULL;
	
    if (ngx_handle_read_event(s->connection->read, 0) != NGX_OK) {
        ngx_tcp_finalize_session(s);
        return;
    }

#if (NGX_TCP_SSL)

    /* 
     * The ssl connection with client may not trigger the read event again,
     * So I trigger it in this function.
     * */
    if (s->connection->ssl) {
        ngx_xmpp_proxy_handler(s->connection->read); 
    }

#endif

    return;
}

void
ngx_xmpp_upstream_handler(ngx_event_t *ev) 
{
    char                     *action, *recv_action, *send_action;
    off_t                    *read_bytes, *write_bytes;
    size_t                    size;
    ssize_t                   n;
    ngx_buf_t                *b;
    ngx_err_t                 err;
    ngx_uint_t               first_read;
    ngx_connection_t         *c;
	ngx_tcp_upstream_conf_t  *usconf;
	ngx_xmpp_upstream_ctx_t	 *ctx;
    //ngx_tcp_core_srv_conf_t  *cscf;

    c = ev->data;
	ctx = c->data;
    usconf = ctx->conf;
    action = "nginx xmpp upstream proxying";
    //cscf = ngx_tcp_get_module_srv_conf(s, ngx_tcp_core_module);

    if (ev->timedout) {
        c->log->action = "upstream processing";

        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT, "upstream timed out");
        c->timedout = 1;

        ngx_tcp_upstream_close(c);
        return;
    }
	
	
#if (NGX_TCP_SSL)
    /* SSL Need this */
    if (s->connection->ssl) {
        first_read = 1;
    }
#else
    first_read = 0;
#endif
    read_bytes = NULL;
    write_bytes = NULL;

	if (ev->write) {
		recv_action = "upstream write: proxying and reading from client";
		send_action = "upstream write: proxying and sending to upstream";
		//b = s->buffer;
		//read_bytes = &s->bytes_read;
		
		n = ngx_tcp_xmpp_upstream_send(ctx,NULL, 0);

		ngx_log_debug1(NGX_LOG_DEBUG_TCP, ev->log, 0,
					   "xmpp upstream handler send:%d", n);

		if (n == NGX_ERROR) {
			ngx_tcp_upstream_close(c);
			return;
		}
		
	} else {
		recv_action = "upstream read: proxying and reading from upstream";
		send_action = "upstream read: proxying and sending to client";
		//dst = s->connection;
		b = c->buffer;
		//write_bytes = &s->bytes_write;
		
		for ( ;; ) {
/*
			if (do_write) {

				size = b->last - b->pos;

				if (size) {
					c->log->action = send_action;

					n = ngx_tcp_xmpp_upstream_send(dst,b->pos, size);
					

					ngx_log_debug1(NGX_LOG_DEBUG_TCP, ev->log, 0,
								   "xmpp proxy handler send:%d", n);

					if (n == NGX_ERROR) {
						ngx_tcp_finalize_session(s);
						return;
					}

					if (n > 0) {
						if (write_bytes) {
							*write_bytes += n;
						}
					}
					b->pos = b->start;
					b->last = b->start;
				}
			}
*/
			size = b->end - b->last;

			if (size) {
				if (c->read->ready || first_read) { 

					first_read = 0;
					c->log->action = recv_action;

					n = c->recv(c, b->last, size);
					err = ngx_socket_errno;
#if (NGX_DEBUG)
if (n > 0)
	b->last[n] = '\0';
else 
	b->last[0] = '\0';
#endif
					ngx_log_debug2(NGX_LOG_DEBUG_TCP, ev->log, 0,
								   "xmpp upstream handler recv:%d, %s", n,b->last);

					if (n == NGX_AGAIN || n == 0) {
						break;
					}

					if (n > 0) {
						//do_write = 1;
						//b->last += n;

						//if (read_bytes) {
						//	*read_bytes += n;
						//}
			
						if (XML_Parse(ctx->xmlparser, b->pos, n, 0) == XML_STATUS_ERROR) {
							
							int errCode=XML_GetErrorCode(ctx->xmlparser);
							if(errCode==36){
								ngx_log_error(NGX_LOG_INFO, c->log, 0, "Parse error (%d) %s",XML_GetErrorCode(ctx->xmlparser),
											  XML_ErrorString(XML_GetErrorCode(ctx->xmlparser)));
							}else{
								ngx_log_error(NGX_LOG_INFO, c->log, 0, "Parse error at line %d:(%d) %s\n",
										XML_GetCurrentLineNumber(ctx->xmlparser),XML_GetErrorCode(ctx->xmlparser),
										XML_ErrorString(XML_GetErrorCode(ctx->xmlparser)));
							}
							ngx_tcp_upstream_close(c);
							return;
						}
						if(ctx->state == XMPP_CM_ERROR){
							ngx_tcp_upstream_close(c);
							return;
						}
						
						continue;
					}

					if (n == NGX_ERROR) {
						c->read->eof = 1;
					}
				}
			}

			break;
		}
		

		if (c->read->eof
                && c->buffer->pos == c->buffer->last)
		{
			
			c->log->action = NULL;
			ngx_log_error(NGX_LOG_DEBUG, c->log, 0, "upstream session done");
			c->log->action = action;

			ngx_tcp_upstream_close(c);
			return;
		}
		
		b->pos = b->start;
		b->last = b->start;
	}

    //do_write = ev->write ? 1 : 0;

	c->log->action = action;

    ngx_log_debug3(NGX_LOG_DEBUG_TCP, ev->log, 0,
                   "xmpp upstream handler: %d, #%d, time:%ui",
                   ev->write, c->fd, ngx_current_msec);
 

    if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
        ngx_tcp_upstream_close(c);
        return;
    }

    if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
        ngx_tcp_upstream_close(c);
        return;
    }

    //if (c == pctx->upstream->connection) {
	if (ev->write) {
		ngx_add_timer(c->write, usconf->send_timeout);
	} else {
		ngx_add_timer(c->read, usconf->read_timeout);
	}
    //}

    return;
}

 void
ngx_xmpp_proxy_handler(ngx_event_t *ev) 
{
    char                     *action, *send_action;
    off_t                    *read_bytes, *write_bytes;
    size_t                    size;
    ssize_t                   n;
    ngx_buf_t                *b;
    ngx_err_t                 err;
    ngx_uint_t                do_write, first_read;
    ngx_connection_t         *c, *src, *dst;
    ngx_tcp_session_t        *s;
	ngx_xmpp_proxy_ctx_t     *pctx;
	ngx_peer_connection_t 	 *pc;
    ngx_xmpp_upstream_ctx_t  *upctx;
    ngx_tcp_core_srv_conf_t  *cscf;

    c = ev->data;
    s = c->data;

    if (ev->timedout) {
        c->log->action = "proxying";

        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT, "proxy timed out");
        c->timedout = 1;

        ngx_tcp_finalize_session(s);
        return;
    }
	
	cscf = ngx_tcp_get_module_srv_conf(s, ngx_tcp_core_module);
	
	upctx = (ngx_xmpp_upstream_ctx_t *) ((u_char *) s->upstream->peer - offsetof(ngx_xmpp_upstream_ctx_t, peer)) ;//s->upstream->peer->connection->data;
	if(upctx->state != XMPP_CM_READY){
		ngx_xmpp_proxy_event_add(upctx,ev);
		ngx_add_timer(c->read, cscf->timeout);
		return;
	}
	
	pc = s->upstream->peer;
	if(ngx_tcp_check_peer_down(pc->check_index)){
		ngx_xmpp_proxy_event_add(upctx,ev);
		if (c->read->timer_set) {
			ngx_del_timer(c->read);
		}
		ngx_add_timer(c->read, cscf->timeout);
		ngx_tcp_upstream_next(upctx,0);
		return;
	}

    read_bytes = NULL;
    write_bytes = NULL;
	pctx = ngx_tcp_get_module_ctx(s, ngx_xmpp_proxy_module);
 
        if (ev->write) {
            //c->log->action = "client write: proxying and reading from upstream";
            c->log->action = "client write: proxying and sending to client";
            src = s->upstream->peer? s->upstream->peer->connection : NULL;
            dst = c;
            //b = pctx->buffer;
            write_bytes = &s->bytes_write;
			
        } else {
            c->log->action = "client read: proxying and reading from client";
            send_action = "client read: proxying and sending to upstream";
            src = c;
            dst = pc ? s->upstream->peer->connection : NULL;
            b = s->buffer;
            read_bytes = &s->bytes_read;
			
			for ( ;; ) {
/*
				if (do_write) {

						size = b->last - b->pos;

						if (size && dst->write->ready) {
							c->log->action = send_action;

							n = dst->send(dst, b->pos, size);
							err = ngx_socket_errno;

							ngx_log_debug1(NGX_LOG_DEBUG_TCP, ev->log, 0,
										   "xmpp proxy handler send:%d", n);

							if (n == NGX_ERROR) {
								ngx_log_error(NGX_LOG_ERR, c->log, err, "proxy send error");

								ngx_tcp_finalize_session(s);
								return;
							}

							if (n > 0) {
								b->pos += n;

								if (write_bytes) {
									*write_bytes += n;
								}

								if (b->pos == b->last) {
									b->pos = b->start;
									b->last = b->start;
								}
							}
						}
					}
*/
				size = b->end - b->last;

				if (size) {
					if (src->read->ready || first_read) { 

						first_read = 0;

						n = src->recv(src, b->last, size);
						err = ngx_socket_errno;
#if (NGX_DEBUG)
		if (n > 0)
			b->last[n] = '\0';
		else 
			b->last[0] = '\0';
#endif
						ngx_log_debug2(NGX_LOG_DEBUG_TCP, ev->log, 0,
									   "xmpp proxy handler recv:%d, %s", n, b->last);

						if (n == NGX_AGAIN || n == 0) {
							break;
						}

						if (n > 0) {
							do_write = 1;
							//b->last += n;

							if (read_bytes) {
								*read_bytes += n;
							}

							if (XML_Parse(pctx->xmlparser, b->pos, n, 0) == XML_STATUS_ERROR) {
								int errCode=XML_GetErrorCode(pctx->xmlparser);
								if(errCode==36){
									ngx_log_debug2(NGX_LOG_DEBUG_TCP, ev->log, 0,
												   "xml parser error(%d): %s",XML_GetErrorCode(pctx->xmlparser),
												   XML_ErrorString(XML_GetErrorCode(pctx->xmlparser)));
								}else{
									ngx_log_debug3(NGX_LOG_DEBUG_TCP, ev->log, 0,
												   "Parse error at line %lu:(%d) %s",XML_GetCurrentLineNumber(pctx->xmlparser),XML_GetErrorCode(pctx->xmlparser),
												   XML_ErrorString(XML_GetErrorCode(pctx->xmlparser)));
								}
								ngx_tcp_finalize_session(s);
								return;
							}
							if (pctx->xml_state == XMPP_SESSION_CLOSE){
								ngx_tcp_xmpp_proxy_send(c,"</stream:stream>",16);
								ngx_tcp_finalize_session(s);
								return;
							}
							
							continue;
						}

						if (n == NGX_ERROR) {
							src->read->eof = 1;
						}
					}
				}

				break;
			}
        }

    do_write = ev->write ? 1 : 0;

#if (NGX_TCP_SSL)
    /* SSL Need this */
    if (s->connection->ssl) {
        first_read = 1;
    }
#else
    first_read = 0;
#endif
	
	if(dst)
    ngx_log_debug4(NGX_LOG_DEBUG_TCP, ev->log, 0,
                   "xmpp proxy handler: %d, #%d > #%d, time:%ui",
                   do_write, src->fd, dst->fd, ngx_current_msec);
	else
		ngx_log_debug3(NGX_LOG_DEBUG_TCP, ev->log, 0,
					   "xmpp proxy handler: %d, #%d , time:%ui",
					   do_write, src->fd, ngx_current_msec);

    //c->log->action = "nginx xmpp proxying";

    if ((s->connection->read->eof && s->buffer->pos == s->buffer->last)
            || (pc && pc->connection && ((pc->connection->read->eof
                && pc->connection->buffer->pos == pc->connection->buffer->last)
            || (s->connection->read->eof && pc->connection->read->eof))))
    {
        action = c->log->action;
        c->log->action = NULL;
        ngx_log_error(NGX_LOG_DEBUG, c->log, 0, "proxied session done");
        c->log->action = action;

        ngx_tcp_finalize_session(s);
        return;
    }
	
	n = ngx_tcp_xmpp_proxy_send(c,NULL,0);
	if(n == NGX_ERROR) {
		ngx_tcp_finalize_session(s);
		return;
	}
	
	
	if (c->read->timer_set) {
        ngx_del_timer(c->read);
    }
	
	if(dst){
		if (ngx_handle_write_event(dst->write, 0) != NGX_OK) {
			ngx_tcp_finalize_session(s);
			return;
		}

		if (ngx_handle_read_event(dst->read, 0) != NGX_OK) {
			ngx_tcp_finalize_session(s);
			return;
		}
	}

	if(src){
		if (ngx_handle_write_event(src->write, 0) != NGX_OK) {
			ngx_tcp_finalize_session(s);
			return;
		}

		if (ngx_handle_read_event(src->read, 0) != NGX_OK) {
			ngx_tcp_finalize_session(s);
			return;
		}
	}

    ngx_add_timer(c->read, cscf->timeout);


    return;
}


static char *
ngx_xmpp_proxy_pass(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) 
{
    ngx_xmpp_proxy_conf_t *pcf = conf;

    u_short                     port = 80;
    ngx_str_t                  *value, *url = &pcf->url;
    ngx_url_t                   u;
    ngx_tcp_core_srv_conf_t    *cscf;

    cscf = ngx_tcp_conf_get_module_srv_conf(cf, ngx_tcp_core_module);

    if (cscf->protocol && ngx_strncmp(cscf->protocol->name.data,
                                      (u_char *)"tcp_generic",
                                      sizeof("tcp_generic") - 1) != 0) {

        return "the protocol should be tcp_generic";
    }

    if (cscf->protocol == NULL) {
        cscf->protocol = &ngx_tcp_xmpp_protocol;
    }

    if (pcf->upstream.upstream) {
        return "is duplicate";
    }

    value = cf->args->elts;

    url = &value[1];

    ngx_memzero(&u, sizeof(u));

    u.url.len = url->len;
    u.url.data = url->data;
    u.default_port = port;
    u.uri_part = 1;
    u.no_resolve = 1;

    pcf->upstream.upstream = ngx_tcp_upstream_add(cf, &u, 0);
    if (pcf->upstream.upstream == NULL) {
        return NGX_CONF_ERROR;
    }

	CS_HT = ngx_hashtable_create(cf->pool,100000);
	
    return NGX_CONF_OK;
}


static void *
ngx_xmpp_proxy_create_conf(ngx_conf_t *cf) 
{
    ngx_xmpp_proxy_conf_t  *pcf;

    pcf = ngx_pcalloc(cf->pool, sizeof(ngx_xmpp_proxy_conf_t));
    if (pcf == NULL) {
        return NULL;
    }

    pcf->buffer_size = NGX_CONF_UNSET_SIZE;

    pcf->upstream.connect_timeout = NGX_CONF_UNSET_MSEC;
    pcf->upstream.send_timeout = NGX_CONF_UNSET_MSEC;
    pcf->upstream.read_timeout = NGX_CONF_UNSET_MSEC;

	
    return pcf;
}


static char *
ngx_xmpp_proxy_merge_conf(ngx_conf_t *cf, void *parent, void *child) 
{
    ngx_xmpp_proxy_conf_t *prev = parent;
    ngx_xmpp_proxy_conf_t *conf = child;

    ngx_conf_merge_size_value(conf->buffer_size, prev->buffer_size,
                              (size_t) ngx_pagesize);

    ngx_conf_merge_msec_value(conf->upstream.connect_timeout,
                              prev->upstream.connect_timeout, 60000);

    ngx_conf_merge_msec_value(conf->upstream.send_timeout,
                              prev->upstream.send_timeout, 60000);

    ngx_conf_merge_msec_value(conf->upstream.read_timeout,
                              prev->upstream.read_timeout, 60000);

    return NGX_CONF_OK;
}
