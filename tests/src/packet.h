#ifndef _NGX_PACKET_H_INCLUDED_
#define _NGX_PACKET_H_INCLUDED_

typedef struct {
	uint32_t	chid;
	uint32_t	len;
}packet_head;

typedef struct {
	ngx_queue_t	queue;
	ngx_str_t	data;
	int 		msg_type;
}xmpp_packet_t;

typedef struct {
	XML_Parser parser;
	int	depth;
	int packet_type;
	ngx_queue_t	uw_queue;
	ngx_queue_t	cw_queue;
	xmpp_packet_t	*packet;
}req_ctx_t;

#endif

