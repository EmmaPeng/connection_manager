
#ifndef _NGX_TCP_XMPP_H_INCLUDED_
#define _NGX_TCP_XMPP_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_tcp.h>
#include <ngx_hashtable.h>
#include <ngx_tcp_session.h>
#include <ngx_tcp_upstream.h>
#include <ngx_xmpp_connection_pool.h>
#include <ngx_tcp_upstream_check.h>
#include <ngx_tcp_upstream_round_robin.h>


void XMLCALL ngx_xmpp_proxy_xmlend(void *data, const char *el);
void XMLCALL ngx_xmpp_proxy_xmlstart(void *data, const char *el, const char **attr);
void XMLCALL ngx_xmpp_upstream_xmlend(void *data, const char *el);
void XMLCALL ngx_xmpp_upstream_xmlstart(void *data, const char *el, const char **attr);

extern ngx_tcp_connection_pool_t		*CONN_POOL;
extern ngx_hashtable_t		*CS_HT;

#define XML_CM2S_CONNECTION "<stream:stream xmlns:stream=\"http://etherx.jabber.org/streams\" xmlns=\"jabber:connectionmanager\" to=\"%s\" version=\"1.0\">"
#define XML_CM2S_CONNECTION_LEN strlen(XML_CM2S_CONNECTION)
#define XML_CM2S_CREATE_SESSION "<iq type='set' to='etop.com' from='%s' id='%s'><session xmlns='http://jabber.org/protocol/connectionmanager' id='%s'><create><host name='%s' address='%s' /></create></session></iq>"
#define XML_CM2S_CREATE_SESSION_LEN strlen(XML_CM2S_CREATE_SESSION)
#define XML_CM2S_CLOSE "<iq type='set' to='etop.com' from='%s' id='%s'><session xmlns='http://jabber.org/protocol/connectionmanager' id='%s'><close /></session></iq>"
#define XML_CM2S_CLOSE_LEN strlen(XML_CM2S_CLOSE)
#define XML_CM2S_HANDSHAKE "<handshake>%s</handshake>"
#define XML_CM2S_HANDSHAKE_LEN strlen(XML_CM2S_HANDSHAKE)
#define XML_CM2S_COMMON_IQ "<iq type=\"%s\" id=\"%s\" to=\"etop.com\" from=\"%s\">%s</iq>"
#define XML_CM2S_COMMON_IQ_LEN strlen(XML_CM2S_COMMON_IQ)
#define XML_CM2C_FEATURES "<stream:stream xmlns:stream=\"http://etherx.jabber.org/streams\" xmlns=\"jabber:client\" from=\"etop.com\" id=\"%s\" xml:lang=\"en\" version=\"1.0\"><stream:features><mechanisms xmlns=\"urn:ietf:params:xml:ns:xmpp-sasl\"><mechanism>PLAIN</mechanism><mechanism>AASAUTH</mechanism></mechanisms><compression xmlns=\"http://jabber.org/features/compress\"><method>zlib</method></compression><auth xmlns=\"http://jabber.org/features/iq-auth\" /><register xmlns=\"http://jabber.org/features/iq-register\" /></stream:features>"
#define XML_CM2C_FEATURES_LEN strlen(XML_CM2C_FEATURES)
#define XML_CM2C_FEATURES_BIND "<?xml version='1.0' encoding='UTF-8'?><stream:stream xmlns:stream=\"http://etherx.jabber.org/streams\" xmlns=\"jabber:client\" from=\"etop.com\" id=\"%s\" xml:lang=\"en\" version=\"1.0\"><stream:features><bind xmlns=\"urn:ietf:params:xml:ns:xmpp-bind\"/><session xmlns=\"urn:ietf:params:xml:ns:xmpp-session\"/></stream:features>"
#define XML_CM2C_FEATURES_BIND_LEN strlen(XML_CM2C_FEATURES_BIND)

extern ngx_module_t  ngx_xmpp_proxy_module;

#define XMPP_STREAM_ID_LEN	30
#define XMPP_MAX_CHN_LEN 30

#endif /* _NGX_TCP_SSL_H_INCLUDED_ */
