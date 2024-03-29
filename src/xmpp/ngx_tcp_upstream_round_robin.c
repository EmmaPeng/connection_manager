
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_tcp_xmpp.h>


static ngx_int_t ngx_tcp_upstream_cmp_servers(const void *one, const void *two);
static ngx_uint_t ngx_tcp_upstream_get_peer(ngx_tcp_upstream_rr_peers_t *peers);

static ngx_peer_connection_t           *PEER;
ngx_int_t
ngx_tcp_upstream_init_round_robin(ngx_conf_t *cf,
    ngx_tcp_upstream_srv_conf_t *us)
{
    ngx_url_t                      u;
    ngx_uint_t                     i, j, n;
    ngx_tcp_upstream_server_t     *server;
    ngx_tcp_upstream_rr_peers_t   *peers, *backup;

	PEER = ngx_pcalloc(cf->pool, sizeof(ngx_tcp_upstream_rr_peers_t));
	ngx_tcp_upstream_rr_peer_data_t  *rrp = ngx_palloc(cf->pool, sizeof(ngx_tcp_upstream_rr_peer_data_t));

    if (PEER == NULL || rrp == NULL) {
        return NGX_ERROR;
    }
	PEER->data = rrp;
	
    us->peer.init = ngx_tcp_upstream_init_round_robin_peer;

    if (us->servers) {
        server = us->servers->elts;

        n = 0;

        for (i = 0; i < us->servers->nelts; i++) {
            if (server[i].backup) {
                continue;
            }

            n += server[i].naddrs;
        }

        peers = ngx_pcalloc(cf->pool, sizeof(ngx_tcp_upstream_rr_peers_t)
                              + sizeof(ngx_tcp_upstream_rr_peer_t) * (n - 1));
        if (peers == NULL) {
            return NGX_ERROR;
        }

        peers->single = (n == 1);
        peers->number = n;
        peers->name = &us->host;

        n = 0;

        for (i = 0; i < us->servers->nelts; i++) {
            for (j = 0; j < server[i].naddrs; j++) {
                if (server[i].backup) {
                    continue;
                }

                peers->peer[n].sockaddr = server[i].addrs[j].sockaddr;
                peers->peer[n].socklen = server[i].addrs[j].socklen;
                peers->peer[n].name = server[i].addrs[j].name;
                peers->peer[n].max_fails = server[i].max_fails;
                peers->peer[n].fail_timeout = server[i].fail_timeout;
                peers->peer[n].down = server[i].down;
                peers->peer[n].weight = server[i].down ? 0 : server[i].weight;
                peers->peer[n].current_weight = peers->peer[n].weight;

                if (!server[i].down && us->check_interval) {
                    peers->peer[n].check_index = 
                        ngx_tcp_check_add_peer(cf, us, &server[i].addrs[j],
                                               server[i].max_busy);

                    if (peers->peer[n].check_index
                                     == (ngx_uint_t) NGX_INVALID_CHECK_INDEX) {
                        return NGX_ERROR;
                    }
                }
                else {
                    peers->peer[n].check_index
                                       = (ngx_uint_t) NGX_INVALID_CHECK_INDEX;
                }

                n++;
            }
        }

        us->peer.data = peers;

        ngx_sort(&peers->peer[0], (size_t) n,
                 sizeof(ngx_tcp_upstream_rr_peer_t),
                 ngx_tcp_upstream_cmp_servers);

        /* backup servers */

        n = 0;

        for (i = 0; i < us->servers->nelts; i++) {
            if (!server[i].backup) {
                continue;
            }

            n += server[i].naddrs;
        }

        if (n == 0) {
            return NGX_OK;
        }

        backup = ngx_pcalloc(cf->pool, sizeof(ngx_tcp_upstream_rr_peers_t)
                              + sizeof(ngx_tcp_upstream_rr_peer_t) * (n - 1));
        if (backup == NULL) {
            return NGX_ERROR;
        }

        peers->single = 0;
        backup->single = 0;
        backup->number = n;
        backup->name = &us->host;

        n = 0;

        for (i = 0; i < us->servers->nelts; i++) {
            for (j = 0; j < server[i].naddrs; j++) {
                if (!server[i].backup) {
                    continue;
                }

                backup->peer[n].sockaddr = server[i].addrs[j].sockaddr;
                backup->peer[n].socklen = server[i].addrs[j].socklen;
                backup->peer[n].name = server[i].addrs[j].name;
                backup->peer[n].weight = server[i].weight;
                backup->peer[n].current_weight = server[i].weight;
                backup->peer[n].max_fails = server[i].max_fails;
                backup->peer[n].fail_timeout = server[i].fail_timeout;
                backup->peer[n].down = server[i].down;
                if (!server[i].down && us->check_interval) {
                    backup->peer[n].check_index = 
                        ngx_tcp_check_add_peer(cf, us, &server[i].addrs[j],
                                               server[i].max_busy);

                    if (backup->peer[n].check_index
                                     == (ngx_uint_t) NGX_INVALID_CHECK_INDEX) {
                        return NGX_ERROR;
                    }
                }
                else {
                    backup->peer[n].check_index
                                     = (ngx_uint_t) NGX_INVALID_CHECK_INDEX;
                }

                n++;
            }
        }

        peers->next = backup;

        ngx_sort(&backup->peer[0], (size_t) n,
                 sizeof(ngx_tcp_upstream_rr_peer_t),
                 ngx_tcp_upstream_cmp_servers);

        return NGX_OK;
    }


    /* an upstream implicitly defined by proxy_pass, etc. */
 
#if (nginx_version) >= 1003011
    if (us->port == 0) {
#else
    if (us->port == 0 && us->default_port == 0) {
#endif
        ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                      "no port in upstream \"%V\" in %s:%ui",
                      &us->host, us->file_name, us->line);
        return NGX_ERROR;
    }

    ngx_memzero(&u, sizeof(ngx_url_t));

    u.host = us->host;
#if (nginx_version) >= 1003011
    u.port = us->port;
#else
    u.port = (in_port_t) (us->port ? us->port : us->default_port);
#endif

    if (ngx_inet_resolve_host(cf->pool, &u) != NGX_OK) {
        if (u.err) {
            ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                          "%s in upstream \"%V\" in %s:%ui",
                          u.err, &us->host, us->file_name, us->line);
        }

        return NGX_ERROR;
    }

    n = u.naddrs;

    peers = ngx_pcalloc(cf->pool, sizeof(ngx_tcp_upstream_rr_peers_t)
                              + sizeof(ngx_tcp_upstream_rr_peer_t) * (n - 1));
    if (peers == NULL) {
        return NGX_ERROR;
    }

    peers->single = (n == 1);
    peers->number = n;
    peers->name = &us->host;

    for (i = 0; i < u.naddrs; i++) {
        peers->peer[i].sockaddr = u.addrs[i].sockaddr;
        peers->peer[i].socklen = u.addrs[i].socklen;
        peers->peer[i].name = u.addrs[i].name;
        peers->peer[i].weight = 1;
        peers->peer[i].current_weight = 1;
        peers->peer[i].max_fails = 1;
        peers->peer[i].fail_timeout = 10;
        peers->peer[i].check_index = (ngx_uint_t) NGX_INVALID_CHECK_INDEX;
    }

    us->peer.data = peers;

    /* implicitly defined upstream has no backup servers */

    return NGX_OK;
}


static ngx_int_t
ngx_tcp_upstream_cmp_servers(const void *one, const void *two)
{
    ngx_tcp_upstream_rr_peer_t  *first, *second;

    first = (ngx_tcp_upstream_rr_peer_t *) one;
    second = (ngx_tcp_upstream_rr_peer_t *) two;

    return (first->weight < second->weight);
}


ngx_int_t
ngx_tcp_upstream_init_round_robin_peer(ngx_tcp_session_t *s,
    ngx_tcp_upstream_srv_conf_t *us)
{
    ngx_uint_t                         n;
    ngx_tcp_upstream_rr_peer_data_t  *rrp;

	if(s->upstream->peer == NULL){
		rrp = PEER->data;
		memset(rrp,0,sizeof(ngx_tcp_upstream_rr_peer_data_t));
		memset(PEER,0,sizeof(ngx_peer_connection_t));
		s->upstream->peer = PEER;
		PEER->data = rrp;
	}else
		rrp = s->upstream->peer->data;
	
    rrp->peers = us->peer.data;
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

	
    s->upstream->peer->log = s->connection->log;
    s->upstream->peer->log_error = NGX_ERROR_ERR;
    s->upstream->peer->get = ngx_tcp_upstream_get_round_robin_peer;
    s->upstream->peer->free = ngx_tcp_upstream_free_round_robin_peer;
    s->upstream->peer->tries = rrp->peers->number;
    s->upstream->peer->check_index = NGX_INVALID_CHECK_INDEX;
    s->upstream->peer->name = NULL;
#if (NGX_TCP_SSL)
    s->upstream->peer->set_session =
                               ngx_tcp_upstream_set_round_robin_peer_session;
    s->upstream->peer->save_session =
                               ngx_tcp_upstream_save_round_robin_peer_session;
#endif

    return NGX_OK;
}


ngx_int_t
ngx_tcp_upstream_create_round_robin_peer(ngx_tcp_session_t *s,
    ngx_tcp_upstream_resolved_t *ur)
{
    u_char                            *p;
    size_t                             len;
#if (nginx_version) >= 1005008
    socklen_t                          socklen;
    struct sockaddr                   *sockaddr;
#else
    struct sockaddr_in                *sin;
#endif
    ngx_uint_t                         i, n;
    ngx_tcp_upstream_rr_peers_t       *peers;
    ngx_tcp_upstream_rr_peer_data_t   *rrp;

    rrp = s->upstream->peer->data;

    if (rrp == NULL) {
        rrp = ngx_palloc(s->pool, sizeof(ngx_tcp_upstream_rr_peer_data_t));
        if (rrp == NULL) {
            return NGX_ERROR;
        }

        s->upstream->peer->data = rrp;
    }

    peers = ngx_pcalloc(s->pool, sizeof(ngx_tcp_upstream_rr_peers_t)
                     + sizeof(ngx_tcp_upstream_rr_peer_t) * (ur->naddrs - 1));
    if (peers == NULL) {
        return NGX_ERROR;
    }

    peers->single = (ur->naddrs == 1);
    peers->number = ur->naddrs;
    peers->name = &ur->host;

    if (ur->sockaddr) {
        peers->peer[0].sockaddr = ur->sockaddr;
        peers->peer[0].socklen = ur->socklen;
        peers->peer[0].name = ur->host;
        peers->peer[0].weight = 1;
        peers->peer[0].current_weight = 1;
        peers->peer[0].max_fails = 1;
        peers->peer[0].fail_timeout = 10;
        peers->peer[0].check_index = (ngx_uint_t) NGX_INVALID_CHECK_INDEX;

    } else {

        for (i = 0; i < ur->naddrs; i++) {

#if (nginx_version) >= 1005008
            socklen = ur->addrs[i].socklen;

            sockaddr = ngx_palloc(s->pool, socklen);
            if (sockaddr == NULL) {
                return NGX_ERROR;
            }

            ngx_memcpy(sockaddr, ur->addrs[i].sockaddr, socklen);

            switch (sockaddr->sa_family) {
#if (NGX_HAVE_INET6)
            case AF_INET6:
                ((struct sockaddr_in6 *) sockaddr)->sin6_port = htons(ur->port);
                break;
#endif
            default: /* AF_INET */
                ((struct sockaddr_in *) sockaddr)->sin_port = htons(ur->port);
            }

            p = ngx_pnalloc(s->pool, NGX_SOCKADDR_STRLEN);
            if (p == NULL) {
                return NGX_ERROR;
            }

            len = ngx_sock_ntop(sockaddr, socklen, p, NGX_SOCKADDR_STRLEN, 1);

            peers->peer[i].sockaddr = sockaddr;
            peers->peer[i].socklen = socklen;
#else
            len = NGX_INET_ADDRSTRLEN + sizeof(":65536") - 1;

            p = ngx_pnalloc(s->pool, len);
            if (p == NULL) {
                return NGX_ERROR;
            }

            len = ngx_inet_ntop(AF_INET, &ur->addrs[i], p, NGX_INET_ADDRSTRLEN);
            len = ngx_sprintf(&p[len], ":%d", ur->port) - p;

            sin = ngx_pcalloc(s->pool, sizeof(struct sockaddr_in));
            if (sin == NULL) {
                return NGX_ERROR;
            }

            sin->sin_family = AF_INET;
            sin->sin_port = htons(ur->port);
            sin->sin_addr.s_addr = ur->addrs[i];

            peers->peer[i].sockaddr = (struct sockaddr *) sin;
            peers->peer[i].socklen = sizeof(struct sockaddr_in);
#endif
            peers->peer[i].name.len = len;
            peers->peer[i].name.data = p;
            peers->peer[i].weight = 1;
            peers->peer[i].current_weight = 1;
            peers->peer[i].max_fails = 1;
            peers->peer[i].fail_timeout = 10;
            peers->peer[i].check_index = (ngx_uint_t) NGX_INVALID_CHECK_INDEX;
        }
    }

    rrp->peers = peers;
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

    s->upstream->peer->get = ngx_tcp_upstream_get_round_robin_peer;
    s->upstream->peer->free = ngx_tcp_upstream_free_round_robin_peer;
    s->upstream->peer->tries = rrp->peers->number;
#if (NGX_TCP_SSL)
    s->upstream->peer->set_session =
                               ngx_tcp_upstream_set_round_robin_peer_session;
    s->upstream->peer->save_session =
                               ngx_tcp_upstream_save_round_robin_peer_session;
#endif

    return NGX_OK;
}


ngx_int_t
ngx_tcp_upstream_get_round_robin_peer(ngx_peer_connection_t *pc, void *data)
{
    ngx_tcp_upstream_rr_peer_data_t  *rrp = data;

    time_t                         now;
    uintptr_t                      m;
    ngx_int_t                      rc;
    ngx_uint_t                     i, n;
    ngx_connection_t              *c;
    ngx_tcp_upstream_rr_peer_t    *peer;
    ngx_tcp_upstream_rr_peers_t   *peers;

    ngx_log_debug1(NGX_LOG_DEBUG_TCP, pc->log, 0,
                   "get rr peer, try: %ui", pc->tries);

    now = ngx_time();

    /* ngx_lock_mutex(rrp->peers->mutex); */

    if (rrp->peers->last_cached) {

        /* cached connection */

        c = rrp->peers->cached[rrp->peers->last_cached];
        rrp->peers->last_cached--;

        /* ngx_unlock_mutex(ppr->peers->mutex); */

#if (NGX_THREADS)
        c->read->lock = c->read->own_lock;
        c->write->lock = c->write->own_lock;
#endif

        pc->connection = c;
        pc->cached = 1;

        return NGX_OK;
    }

    pc->cached = 0;
    pc->connection = NULL;

    if (rrp->peers->single) {
        peer = &rrp->peers->peer[0];
        if (ngx_tcp_check_peer_down(peer->check_index)) {
            return NGX_BUSY;
        }
    } else {

        /* there are several peers */

        if (pc->tries == rrp->peers->number) {

            /* it's a first try - get a current peer */

            i = pc->tries;

            for ( ;; ) {
                rrp->current = ngx_tcp_upstream_get_peer(rrp->peers);

                ngx_log_debug3(NGX_LOG_DEBUG_TCP, pc->log, 0,
                               "get rr peer, current: %ui %i, tries: %ui",
                               rrp->current,
                               rrp->peers->peer[rrp->current].current_weight,
                               pc->tries);

                n = rrp->current / (8 * sizeof(uintptr_t));
                m = (uintptr_t) 1 << rrp->current % (8 * sizeof(uintptr_t));

                if (!(rrp->tried[n] & m)) {
                    peer = &rrp->peers->peer[rrp->current];

                    if (!peer->down) {

                        ngx_log_debug1(NGX_LOG_DEBUG_TCP, pc->log, 0,
                                "get rr peer, down: %ui", 
                                ngx_tcp_check_peer_down(peer->check_index));

                        if (!ngx_tcp_check_peer_down(peer->check_index)) {
                            if (peer->max_fails == 0
                                    || peer->fails < peer->max_fails)
                            {
                                break;
                            }

                            if (now - peer->accessed > peer->fail_timeout) {
                                peer->fails = 0;
                                break;
                            }
                        }

                        peer->current_weight = 0;

                    } else {
                        rrp->tried[n] |= m;
                    }

                    pc->tries--;
                }

                if (pc->tries == 0) {
                    goto failed;
                }

                if (--i == 0) {
                    ngx_log_error(NGX_LOG_ALERT, pc->log, 0,
                                  "round robin upstream stuck on %ui tries",
                                  pc->tries);
                    goto failed;
                }
            }

            peer->current_weight--;

        } else {

            i = pc->tries;

            for ( ;; ) {
                n = rrp->current / (8 * sizeof(uintptr_t));
                m = (uintptr_t) 1 << rrp->current % (8 * sizeof(uintptr_t));

                if (!(rrp->tried[n] & m)) {

                    peer = &rrp->peers->peer[rrp->current];

                    if (!peer->down) {

                        if (!ngx_tcp_check_peer_down(peer->check_index)) {
                            
                            if (peer->max_fails == 0
                                    || peer->fails < peer->max_fails)
                            {
                                break;
                            }

                            if (now - peer->accessed > peer->fail_timeout) {
                                peer->fails = 0;
                                break;
                            }
                        }

                        peer->current_weight = 0;

                    } else {
                        rrp->tried[n] |= m;
                    }

                    pc->tries--;
                }

                rrp->current++;

                if (rrp->current >= rrp->peers->number) {
                    rrp->current = 0;
                }

                if (pc->tries == 0) {
                    goto failed;
                }

                if (--i == 0) {
                    ngx_log_error(NGX_LOG_ALERT, pc->log, 0,
                                  "round robin upstream stuck on %ui tries",
                                  pc->tries);
                    goto failed;
                }
            }

            peer->current_weight--;
        }

        rrp->tried[n] |= m;
    }

    pc->sockaddr = peer->sockaddr;
    pc->socklen = peer->socklen;
    pc->name = &peer->name;
    pc->check_index = peer->check_index;

    /* ngx_unlock_mutex(rrp->peers->mutex); */

    if (pc->tries == 1 && rrp->peers->next) {
        pc->tries += rrp->peers->next->number;

        n = rrp->peers->next->number / (8 * sizeof(uintptr_t)) + 1;
        for (i = 0; i < n; i++) {
             rrp->tried[i] = 0;
        }
    }

    return NGX_OK;

failed:

    peers = rrp->peers;

    ngx_log_debug0(NGX_LOG_DEBUG_TCP, pc->log, 0, "backup servers1");

    if (peers->next) {

        /* ngx_unlock_mutex(peers->mutex); */

        ngx_log_debug0(NGX_LOG_DEBUG_TCP, pc->log, 0, "backup servers");

        rrp->peers = peers->next;
        pc->tries = rrp->peers->number;

        n = rrp->peers->number / (8 * sizeof(uintptr_t)) + 1;
        for (i = 0; i < n; i++) {
             rrp->tried[i] = 0;
        }

        rc = ngx_tcp_upstream_get_round_robin_peer(pc, rrp);

        if (rc != NGX_BUSY) {
            return rc;
        }

        /* ngx_lock_mutex(peers->mutex); */
    }

    /* all peers failed, mark them as live for quick recovery */

    for (i = 0; i < peers->number; i++) {
        peers->peer[i].fails = 0;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_TCP, pc->log, 0, "backup servers2");

    /* ngx_unlock_mutex(peers->mutex); */

    pc->name = peers->name;

    return NGX_BUSY;
}


static ngx_uint_t
ngx_tcp_upstream_get_peer(ngx_tcp_upstream_rr_peers_t *peers)
{
    ngx_uint_t                    i, n;
    ngx_tcp_upstream_rr_peer_t   *peer;

    peer = &peers->peer[0];

    for ( ;; ) {

        for (i = 0; i < peers->number; i++) {

            if (peer[i].current_weight <= 0) {
                continue;
            }

            n = i;

            while (i < peers->number - 1) {

                i++;

                if (peer[i].current_weight <= 0) {
                    continue;
                }

                if (peer[n].current_weight * 1000 / peer[i].current_weight
                    > peer[n].weight * 1000 / peer[i].weight)
                {
                    return n;
                }

                n = i;
            }

            if (peer[i].current_weight > 0) {
                n = i;
            }

            return n;
        }

        for (i = 0; i < peers->number; i++) {
            peer[i].current_weight = peer[i].weight;
        }
    }
}


void
ngx_tcp_upstream_free_round_robin_peer(ngx_peer_connection_t *pc, void *data,
    ngx_uint_t state)
{
    ngx_tcp_upstream_rr_peer_data_t  *rrp = data;

    time_t                       now;
    ngx_tcp_upstream_rr_peer_t  *peer;

    ngx_log_debug2(NGX_LOG_DEBUG_TCP, pc->log, 0,
                   "free rr peer %ui %ui", pc->tries, state);

    if (state == 0 && pc->tries == 0) {
        return;
    }

    /* TODO: NGX_PEER_KEEPALIVE */

    if (rrp->peers->single) {
        pc->tries = 0;
        return;
    }

    if (state & NGX_PEER_FAILED) {
        now = ngx_time();

        /* ngx_lock_mutex(rrp->peers->mutex); */
        peer = &rrp->peers->peer[rrp->current];

        peer->fails++;
        peer->accessed = now;

        if (peer->max_fails) {
            peer->current_weight -= peer->weight / peer->max_fails;
        }

        ngx_log_debug2(NGX_LOG_DEBUG_TCP, pc->log, 0,
                       "free rr peer failed: %ui %i",
                       rrp->current, peer->current_weight);

        if (peer->current_weight < 0) {
            peer->current_weight = 0;
        }

        /* ngx_unlock_mutex(rrp->peers->mutex); */
    }

    rrp->current++;

    if (rrp->current >= rrp->peers->number) {
        rrp->current = 0;
    }

    if (pc->tries) {
        pc->tries--;
    }

    /* ngx_unlock_mutex(rrp->peers->mutex); */
}


#if (NGX_TCP_SSL)

ngx_int_t
ngx_tcp_upstream_set_round_robin_peer_session(ngx_peer_connection_t *pc,
    void *data)
{
    ngx_tcp_upstream_rr_peer_data_t  *rrp = data;

    ngx_int_t                     rc;
    ngx_ssl_session_t            *ssl_session;
    ngx_tcp_upstream_rr_peer_t   *peer;

    peer = &rrp->peers->peer[rrp->current];

    /* TODO: threads only mutex */
    /* ngx_lock_mutex(rrp->peers->mutex); */

    ssl_session = peer->ssl_session;

    rc = ngx_ssl_set_session(pc->connection, ssl_session);

    ngx_log_debug2(NGX_LOG_DEBUG_TCP, pc->log, 0,
                   "set session: %p:%d",
                   ssl_session, ssl_session ? ssl_session->references : 0);

    /* ngx_unlock_mutex(rrp->peers->mutex); */

    return rc;
}


void
ngx_tcp_upstream_save_round_robin_peer_session(ngx_peer_connection_t *pc,
    void *data)
{
    ngx_tcp_upstream_rr_peer_data_t  *rrp = data;

    ngx_ssl_session_t            *old_ssl_session, *ssl_session;
    ngx_tcp_upstream_rr_peer_t  *peer;

    ssl_session = ngx_ssl_get_session(pc->connection);

    if (ssl_session == NULL) {
        return;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_TCP, pc->log, 0,
                   "save session: %p:%d", ssl_session, ssl_session->references);

    peer = &rrp->peers->peer[rrp->current];

    /* TODO: threads only mutex */
    /* ngx_lock_mutex(rrp->peers->mutex); */

    old_ssl_session = peer->ssl_session;
    peer->ssl_session = ssl_session;

    /* ngx_unlock_mutex(rrp->peers->mutex); */

    if (old_ssl_session) {

        ngx_log_debug2(NGX_LOG_DEBUG_TCP, pc->log, 0,
                       "old session: %p:%d",
                       old_ssl_session, old_ssl_session->references);

        /* TODO: may block */

        ngx_ssl_free_session(old_ssl_session);
    }
}

#endif
