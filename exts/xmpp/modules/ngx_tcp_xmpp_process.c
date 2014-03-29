
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_sha1.h>
#include <ngx_crypt.h>
#include <ngx_tcp.h>
#include <expat.h>
#include <ngx_tcp_xmpp.h>

void XMLCALL
ngx_xmpp_proxy_xmlstart(void *data, const char *el, const char **attr)
{
	ngx_uint_t				i;
	XML_Parser				parser;
	ngx_tcp_session_t 		*s;
	ngx_connection_t        *c;
	ngx_xmpp_upstream_ctx_t	*ctx;
	ngx_buf_t               *b;
	
	s = (ngx_tcp_session_t*)data;
	parser=s->xmlparser;
	if(s->upstream->peer == NULL || (c=s->upstream->peer->connection) == NULL){
		//ngx_tcp_finalize_session(s);
		XML_StopParser(parser,0);
		s->xml_state = XMPP_SESSION_ERROR;
        return;
	}
	ctx = c->data;
	b = ctx->wbuffer;

#if (NGX_DEBUG)
	for (i = 0; i < s->xml_depth; i++)
		printf("\t");

	printf("%lu: %s",s->xml_depth, el);

	for (i = 0; attr[i]; i += 2) {
		printf(" %s='%s'", attr[i], attr[i + 1]);
	}

	printf("\n");
#endif
	
	if(s->xml_depth==1){
		s->xml_pre_index=XML_GetCurrentByteIndex(parser);
	}else if(s->xml_depth==0){
		if(ngx_memcmp("stream:stream",el,13) == 0){
			int size;//preSize,preOffset;
			//char *str=XML_GetInputContext(parser, &preOffset, &preSize);
			//s->xml_pre_index=preOffset;
			//int sbuflen=strlen(str);
			//char *sbuf=ngx_pcalloc(pool,sbuflen);
			//memcpy(sbuf,str,sbuflen);
			size = XML_CM2S_CREATE_SESSION_LEN + ctx->xml_tofrom.len + s->channel_id.len * 2 + s->connection->addr_text.len *2 - 10;
			if(b->end - b->last < size)
				if(ngx_tcp_xmpp_upstream_send(ctx,NULL,0) == NGX_ERROR){
					XML_StopParser(parser,0);
					s->xml_state = XMPP_SESSION_ERROR;
					return;
				}
			
			sprintf((char*)b->last, XML_CM2S_CREATE_SESSION, (char*)ctx->xml_tofrom.data, (char*)s->channel_id.data, (char*)s->channel_id.data, (char*)s->connection->addr_text.data, (char*)s->connection->addr_text.data);
			//ngx_copy(b->last,XML_CM2S_CREATE_SESSION,XML_CM2S_CREATE_SESSION_LEN);
			b->last+=size;
			//ngx_copy(b->last,s->channel_id.data,s->channel_id.len);
			if(ngx_tcp_xmpp_upstream_send(ctx,NULL,0) == NGX_ERROR){
				XML_StopParser(parser,0);
				s->xml_state = XMPP_SESSION_ERROR;
			}
			//ngx_tcp_xmpp_proxy_send(s->connection,str,sbuflen);
		}
	}

	s->xml_depth++;

}

void XMLCALL
ngx_xmpp_proxy_xmlend(void *data, const char *el)
{
	XML_Parser				parser;
	ngx_tcp_session_t 		*s;
	ngx_connection_t        *c;
	ngx_xmpp_upstream_ctx_t	*ctx;
	ngx_buf_t               *b;
	
	s = (ngx_tcp_session_t*)data;
	parser=s->xmlparser;
	if(s->upstream->peer == NULL || (c=s->upstream->peer->connection) == NULL){
		//ngx_tcp_finalize_session(s);
		XML_StopParser(parser,1);
		s->xml_state = XMPP_SESSION_ERROR;
        return;
	}
	ctx = c->data;
	b = ctx->wbuffer;

	s->xml_depth--;
	
	if(s->xml_depth==1){
		int offset,size,index;
		char *str;
		
		// 19 => 17+2
		if(b->end - b->last < (19+s->channel_id.len) && ngx_tcp_xmpp_upstream_send(ctx,NULL,0) == NGX_ERROR){
			XML_StopParser(parser,0);
			s->xml_state = XMPP_SESSION_ERROR;
			return;
		}
		ngx_copy(b->last,(u_char*)"<route streamid=\"",17);
		b->last += 17;
		ngx_copy(b->last,s->channel_id.data,s->channel_id.len);
		b->last += s->channel_id.len;
		ngx_copy(b->last,(u_char*)"\">",2);
		b->last += 2;
		
		index=XML_GetCurrentByteIndex(parser);
		str = XML_GetInputContext(parser, &offset, &size);
		size = index - s->xml_pre_index + strlen(el)+3;
		if(b->end - b->last < size && ngx_tcp_xmpp_upstream_send(ctx,NULL,0) == NGX_ERROR){
			XML_StopParser(parser,0);
			s->xml_state = XMPP_SESSION_ERROR;
			return;
		}
		b->last = ngx_copy(b->last,str + (offset-(index - s->xml_pre_index)),size);
		if(ngx_tcp_xmpp_upstream_send(ctx,(u_char*)"</route>",8) == NGX_ERROR){
			XML_StopParser(parser,0);
			s->xml_state = XMPP_SESSION_ERROR;
		}
//	printf("pre-offset: %d, offset: %d, size: %d, xml_depth: %d, %s, %s\n",preOffset, offset,size ,ctx->xml_depth, sbuf,el);
	}else if(s->xml_depth == 0){
		s->xml_state = XMPP_SESSION_CLOSE;
	}
}

ngx_int_t ngx_tcp_xmpp_proxy_send(ngx_connection_t *c,u_char *data,size_t len){
	size_t                 	n=0,size;
	ngx_buf_t				*b;
	//u_char					*p;
	ngx_tcp_session_t       *s;
	ngx_err_t            	err;
	
	s = c->data;
	b = s->wbuffer;
	
	if (c->write->ready) {
		c->log->action = "client write: proxying and sending to client";
		size = b->last - b->pos;
		if(size){
			n = c->send(c, b->pos, size);
			err = ngx_socket_errno;
#if (NGX_DEBUG)
		if(n>0)
			b->pos[n] = '\0';
		else
			b->pos[0] = '\0';
#endif
			ngx_log_debug2(NGX_LOG_DEBUG_TCP, c->log, 0,
						   "tcp proxy handler send:%d, %s", n, b->pos);

			if (n == (size_t)NGX_ERROR) {
				ngx_log_error(NGX_LOG_ERR, c->log, err, "proxy send error");
				return NGX_ERROR;
			}
			if(n>0){
				b->pos += n;
				if (n != size) {
					ngx_log_error(NGX_LOG_ERR, c->log, err, "send error: data size:%zd, send size:%d",size,n);
					n = 0;
					goto cache;
				}
			}
			
			if (b->pos == b->last) {
				b->pos = b->start;
				b->last = b->start;
			}
		}
	}
	
	if(len <= 0)
			return NGX_OK;
	
	//printf("%s, %zd\n",data,len);
	
	if(c->write->ready){
		n = c->send(c, data, len);
		err = ngx_socket_errno;

		ngx_log_debug2(NGX_LOG_DEBUG_TCP, c->log, 0,
					   "xmpp proxy handler send:%d, %s", n, data);

		if (n == (size_t)NGX_ERROR) {
			ngx_log_error(NGX_LOG_ERR, c->log, err, "proxy send error");
			return NGX_ERROR;
		}
		if(n>0){
			if (n != len) {
				ngx_log_error(NGX_LOG_ERR, c->log, err, "send error: data size:%zd, send size:%d",len,n);
				
				goto cache;
			}
			return NGX_OK;
		}
	}
	n = 0;
	
cache:	
	
	size = len-n;
	if(size <= 0) return NGX_OK;
	
	if((size_t)(b->end - b->last) < size){
		ngx_log_error(NGX_LOG_ERR, c->log, err, "cache error: data size:%zd, buff size:%d",size,(b->end - b->last));
		return NGX_ERROR;
	}
	ngx_copy(b->last,data+n,size);
	b->last += size;
	if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
		return NGX_ERROR;
	}
	
	return NGX_AGAIN;
}

void XMLCALL
ngx_xmpp_upstream_xmlstart(void *data, const char *el, const char **attr)
{
	ngx_uint_t 				i;
	ngx_connection_t        *c;
	XML_Parser				parser;
	ngx_xmpp_upstream_ctx_t	*ctx;
	ngx_tcp_session_t		*s;
	ngx_buf_t				*b;
	
	c = (ngx_connection_t*)data;
	ctx = c->data;
	parser = ctx->xmlparser;

#if (NGX_DEBUG)
	
	for (i = 0; i < ctx->xml_depth; i++)
		printf("\t");

	printf("%lu: %s",ctx->xml_depth, el);

	for (i = 0; attr[i]; i += 2) {
		printf(" %s='%s'", attr[i], attr[i + 1]);
	}
	printf("\n");
#endif
	
	if(ctx->state == XMPP_CM_READY){
		int len;
		if(ctx->xml_depth==1){
			if(ngx_memcmp("route",el,5) == 0){
				ctx->xmpp_type = XMPP_ROUTE;
				ctx->channel_id.len=0;
				for (i = 0; attr[i]; i += 2) {
					len=strlen(attr[i]);
					if(len == 8 && memcmp(attr[i],"streamid",8)==0){
						ctx->channel_id.len=strlen(attr[i + 1]);
						ngx_copy(ctx->channel_id.data,attr[i + 1],ctx->channel_id.len);
						ctx->channel_id.data[ctx->channel_id.len] = '\0';
					}
				}
				ctx->xml_pre_index = 0;
			}else if(ngx_memcmp("iq",el,2) == 0){
				for (i = 0; attr[i]; i += 2) {
					len=strlen(attr[i]);
					if(len == 4 && memcmp(attr[i],"type",4)==0){
						if(ngx_memcmp("set",attr[i + 1],3) == 0)
							ctx->xmpp_type = XMPP_IQ_SET;
						else if(ngx_memcmp("result",attr[i + 1],6) == 0)
							ctx->xmpp_type = XMPP_IQ_RESULT;
						else if(ngx_memcmp("error",attr[i + 1],5) == 0){
							ctx->xmpp_type = XMPP_IQ_ERROR;
							XML_StopParser(parser,0);
							//s->xml_state = XMPP_SESSION_ERROR;
						}
					}
				}
				
			}else{
				ctx->xmpp_type = XMPP_UNUSE;
			}
		}else if(ctx->xml_depth==2){
			int 	offset,size,index;
			index = XML_GetCurrentByteIndex(parser);
			switch(ctx->xmpp_type){
				case XMPP_IQ_RESULT:
					if(ngx_memcmp("session",el,7) == 0){
						for (i = 0; attr[i]; i += 2) {
							len=strlen(attr[i]);
							if(len == 2 && memcmp(attr[i],"id",2)==0){
								ctx->channel_id.len=ngx_strlen(attr[i + 1]);
								ngx_copy(ctx->channel_id.data,attr[i + 1],ctx->channel_id.len);
								ctx->channel_id.data[ctx->channel_id.len] = '\0';
							}
						}
					}
					break;
					
				case XMPP_ROUTE:
					if(ctx->xml_pre_index ==0){
						break;
					}

					char *str=XML_GetInputContext(parser, &offset, &size);
					index = XML_GetCurrentByteIndex(parser);
					//size=offset - ctx->xml_pre_index;
					//ngx_log_error(NGX_LOG_ERR, c->log, ngx_socket_errno, "offset: %d, ctx->xml_pre_index: %d,index: %d, strlen(el): %s, size: %d",offset , ctx->xml_pre_index,index,el,size);

					if(ctx->channel_id.len>0 && (s=(ngx_tcp_session_t*)ngx_hashtable_get(CS_HT,ctx->channel_id.data,ctx->channel_id.len))){
						b = s->wbuffer;
						size = index - ctx->xml_pre_index;
						if(b->end - b->last < size && ngx_tcp_xmpp_proxy_send(s->connection,NULL,0) == NGX_ERROR){
							XML_StopParser(parser,0);
							s->xml_state = XMPP_SESSION_ERROR;
							break;
						}
						ngx_copy(b->last,str+(offset - size),size);
						b->last += size;
						
						ctx->xml_pre_index=index;

					}else{
						ngx_log_error(NGX_LOG_ERR, c->log, ngx_socket_errno, "upstream => proxy error, channel_id: %s,len: %d",ctx->channel_id.data,ctx->channel_id.len);
						XML_StopParser(parser,0);
					}
					
					break;
					
				default:
					break;
			};
			ctx->xml_pre_index = index;
		}else if(ctx->xml_depth > 2){
			switch(ctx->xmpp_type){
				case XMPP_ROUTE:{
					int 	offset,size,index;
					char *str=XML_GetInputContext(parser, &offset, &size);
					index = XML_GetCurrentByteIndex(parser);
					//size=offset - ctx->xml_pre_index;
					//ngx_log_error(NGX_LOG_ERR, c->log, ngx_socket_errno, "offset: %d, ctx->xml_pre_index: %d,index: %d, tag: %s, size: %d",offset , ctx->xml_pre_index,index,el,size);
					
					if(ctx->channel_id.len>0 && (s=(ngx_tcp_session_t*)ngx_hashtable_get(CS_HT,ctx->channel_id.data,ctx->channel_id.len))){
						b = s->wbuffer;
						size = index - ctx->xml_pre_index;
						if(b->end - b->last < size && ngx_tcp_xmpp_proxy_send(s->connection,NULL,0) == NGX_ERROR){
							XML_StopParser(parser,0);
							s->xml_state = XMPP_SESSION_ERROR;
							break;
						}
						ngx_copy(b->last,str+(offset - size),size);
						b->last += size;
						
						ctx->xml_pre_index=index;

					}else{
						ngx_log_error(NGX_LOG_ERR, c->log, ngx_socket_errno, "upstream => proxy error, channel_id: %s,len: %d",ctx->channel_id.data,ctx->channel_id.len);
						XML_StopParser(parser,0);
					}

					break;
				}default:
					break;
			};
			
		}
		
	}else{
	
		if(ctx->xml_depth == 0){
			int len;
			for (i = 0; attr[i]; i += 2) {
				len=strlen(attr[i]);
				if(len == 2 && memcmp(attr[i],"id",2)==0){
					ctx->xml_streamid.len = ngx_strlen(attr[i + 1]);
					ngx_copy(ctx->xml_streamid.data,attr[i + 1],ctx->xml_streamid.len);
					ctx->xml_streamid.data[ctx->xml_streamid.len]='\0';
				}
			}
		}else if(ctx->xml_depth==1){
			int len;
			if(ngx_memcmp("iq",el,2) == 0){
				for (i = 0; attr[i]; i += 2) {
					len=strlen(attr[i]);
					if(len == 4 && memcmp(attr[i],"type",4)==0){
						if(ngx_memcmp("set",attr[i + 1],3) == 0)
							ctx->xmpp_type = XMPP_IQ_SET;
						else if(ngx_memcmp("result",attr[i + 1],6) == 0)
							ctx->xmpp_type = XMPP_IQ_RESULT;
						else if(ngx_memcmp("error",attr[i + 1],5) == 0){
							ctx->xmpp_type = XMPP_IQ_ERROR;
							XML_StopParser(parser,0);

						}
					}
				}
			}
		}else if(ctx->xml_depth == 2 ){
			if(ctx->xmpp_type == XMPP_IQ_SET && ngx_memcmp("configuration",el,13) == 0){
				ctx->xml_pre_index = XML_GetCurrentByteIndex(parser);
			}
		}
	
	}

end:

	ctx->xml_depth++;

}

static ngx_int_t
ngx_crypt_sha(u_char *data, size_t len, ngx_str_t *key, ngx_str_t *encrypted)
{
    ngx_sha1_t  sha1;
    u_char      digest[(SHA_DIGEST_LENGTH + 1)*sizeof(u_char)];
	memset(digest, 0, SHA_DIGEST_LENGTH + 1);

    ngx_sha1_init(&sha1);
    ngx_sha1_update(&sha1, data, len);
	ngx_sha1_update(&sha1, key->data, key->len);
	
    ngx_sha1_final(digest, &sha1);

	ngx_hex_dump(encrypted->data,digest,SHA_DIGEST_LENGTH);
	encrypted->data[encrypted->len] = '\0';
    //ngx_encode_base64(encrypted, &decoded);

    return NGX_OK;
}

void XMLCALL
ngx_xmpp_upstream_xmlend(void *data, const char *el)
{
	XML_Parser				parser;
	ngx_tcp_session_t 		*s;
	ngx_connection_t        *c;
	ngx_xmpp_upstream_ctx_t	*ctx;
	ngx_buf_t				*b;
	int 					size;
	
	c = (ngx_connection_t*)data;
	ctx = c->data;
	parser=ctx->xmlparser;
	
	ctx->xml_depth--;
	
	if(ctx->state == XMPP_CM_READY){
		if(ctx->xml_depth==1 ){
			switch(ctx->xmpp_type){
				case XMPP_IQ_RESULT:

					parser=ctx->xmlparser;
					s=(ngx_tcp_session_t*)ngx_hashtable_get(CS_HT,ctx->channel_id.data,ctx->channel_id.len);
					if(s){

						b = s->wbuffer;
						size = XML_CM2C_FEATURES_LEN + ctx->channel_id.len - 2;
						if(b->end - b->last < size)
							if(ngx_tcp_xmpp_proxy_send(s->connection,NULL,0) == NGX_ERROR){
								XML_StopParser(parser,0);
								return;
							}
						
						sprintf(b->last,XML_CM2C_FEATURES,ctx->channel_id.data);
						b->last += size;
						
						if(ngx_tcp_xmpp_proxy_send(s->connection,NULL,0) == NGX_ERROR){
							XML_StopParser(parser,0);
							s->xml_state = XMPP_SESSION_ERROR;
							return;
						}

					}else{
						ngx_log_error(NGX_LOG_ERR, c->log, ngx_socket_errno, "upstream => proxy error, channel_id: %s,len: %d",ctx->channel_id.data,ctx->channel_id.len);
					}
					
					break;
				default:
					break;
			};

		}else if(ctx->xml_depth==2 ){
			switch(ctx->xmpp_type){
				case XMPP_ROUTE:
					parser=ctx->xmlparser;
					s=(ngx_tcp_session_t*)ngx_hashtable_get(CS_HT,ctx->channel_id.data,ctx->channel_id.len);
					if(s){
						int 	offset,size,index;
						char *str=XML_GetInputContext(parser, &offset, &size);
						index = XML_GetCurrentByteIndex(parser);

						size = index - ctx->xml_pre_index;
						str = str+(offset - size);
						if(ngx_tcp_xmpp_proxy_send(s->connection,str,size) == NGX_ERROR){
							XML_StopParser(parser,0);
							return;
						}
						ctx->xml_pre_index = index;
					}else{
						ngx_log_error(NGX_LOG_ERR, c->log, ngx_socket_errno, "upstream => proxy error, channel_id: %s,len: %d",ctx->channel_id.data,ctx->channel_id.len);
					}
					break;
				default:
					break;
			};
			
			
//	printf("pre-offset: %d, offset: %d, size: %d, xml_depth: %d, %s, %s\n",preOffset, offset,size ,ctx->xml_depth, sbuf,el);
		}
		
	}else{
		
		if(ctx->xml_depth==1 ){
			if(ngx_memcmp("stream:features",el,15) == 0){
				int size;
				ngx_str_t encrypted;
				ngx_str_t 	key;
				key.data = "789";
				key.len	= 3;
				
				if(ctx->state != XMPP_CM_CONNECTION){
					ngx_log_error(NGX_LOG_ERR, c->log, ngx_socket_errno, "upstream state error");
					XML_StopParser(parser,0);
					ctx->state = XMPP_CM_ERROR;
					return;
				}
				
				b = ctx->wbuffer;
	
				encrypted.len = 2 * SHA_DIGEST_LENGTH;//20 => len(SHA->hex)   ngx_base64_encoded_length(decoded.len) + 1;
				size = 23 + encrypted.len; // 23 => <handshake></handshake>
				if(b->end - b->last < size)
					if(ngx_tcp_xmpp_upstream_send(ctx,NULL,0) == NGX_ERROR){
						XML_StopParser(parser,0);
						return;
					}
				
				ngx_copy(b->last, (u_char*)"<handshake>",11);
				b->last += 11;
				
				encrypted.data = b->last;
				
				ngx_crypt_sha(ctx->xml_streamid.data, ctx->xml_streamid.len, &key, &encrypted);

				ngx_log_debug3(NGX_LOG_DEBUG_TCP, c->log, 0,"streamid: \"%s\", streamid_len: \"%d\", encrypted: \"%s\"", ctx->xml_streamid.data, ctx->xml_streamid.len, encrypted.data);

				b->last += encrypted.len;
				ngx_copy(b->last, (u_char*)"</handshake>",12);
				b->last += 12;
				
				if(ngx_tcp_xmpp_upstream_send(ctx,NULL,0) == NGX_ERROR){
					XML_StopParser(parser,0);
					return;
				}
				
				ctx->state = XMPP_CM_HANDSHAKE;

			}else if(ngx_memcmp("stream:error",el,12) == 0){
				XML_StopParser(parser,0);
				ctx->state = XMPP_CM_ERROR;
				return;
			}else if(ngx_memcmp("handshake",el,9) == 0){
				if(ctx->state != XMPP_CM_HANDSHAKE){
					ngx_log_error(NGX_LOG_ERR, c->log, ngx_socket_errno, "upstream state error");
					XML_StopParser(parser,0);
					ctx->state = XMPP_CM_ERROR;
					return;
				}
				
				ctx->state = XMPP_CM_CONFIGURATION;
				return;
			}
		}else if(ctx->xml_depth == 2 ){
			if(ngx_memcmp("configuration",el,13) == 0){
				int offset,size,index;
				char *str;
				if(ctx->state != XMPP_CM_CONFIGURATION){
					ngx_log_error(NGX_LOG_ERR, c->log, ngx_socket_errno, "upstream state error");
					XML_StopParser(parser,0);
					ctx->state = XMPP_CM_ERROR;
					return;
				}
				b = ctx->wbuffer;
				
				//39 => 36+3
				size = 39+ctx->xml_streamid.len;
				if(b->end - b->last < size && ngx_tcp_xmpp_upstream_send(ctx,NULL,0) == NGX_ERROR){
					XML_StopParser(parser,0);
					return;
				}
				ngx_copy(b->last, (u_char*)"<iq type=\"result\" to=\"etop.com\" id=\"",36);
				b->last += 36;
				ngx_copy(b->last, ctx->xml_streamid.data, ctx->xml_streamid.len);
				b->last += ctx->xml_streamid.len;
				
				ngx_copy(b->last, (u_char*)"\">",2);
				b->last += 2;
				
				str = XML_GetInputContext(parser, &offset, &size);
				index = XML_GetCurrentByteIndex(parser);

				size = index - ctx->xml_pre_index;
				if(b->end - b->last < size && ngx_tcp_xmpp_upstream_send(ctx,NULL,0) == NGX_ERROR){
					XML_StopParser(parser,0);
					return;
				}

				ngx_copy(b->last, str+(offset - size), size+16);
				b->last += (size+16);

				if(ngx_tcp_xmpp_upstream_send(ctx,"</iq>",5) == NGX_ERROR){
					XML_StopParser(parser,0);
					return;
				}
				ngx_xmpp_upstream_connect_finished(ctx);
				
			}
		}
		
	}
	
}


ngx_int_t
ngx_tcp_xmpp_upstream_send(ngx_xmpp_upstream_ctx_t *ctx,u_char *data,size_t len) {
	size_t                 n=0,size;
	ngx_buf_t               *b;
	ngx_connection_t 		*c;
	ngx_err_t            	err;
	
	c = ctx->peer.connection;
	b = ctx->wbuffer;
	
	if(ctx->destroyed)goto cache;
	
	if (c->write->ready) {
		c->log->action = "client write: proxying and sending to client";
		size = b->last - b->pos;
		if(size){
			n = c->send(c, b->pos, size);
			err = ngx_socket_errno;
#if (NGX_DEBUG)
		if(n>0)
			b->pos[n] = '\0';
		else
			b->pos[0] = '\0';
#endif
			ngx_log_debug2(NGX_LOG_DEBUG_TCP, c->log, 0,
						   "xmpp upstream handler send:%d, %s", n,b->pos);

			if (n == (size_t)NGX_ERROR) {
				ngx_log_error(NGX_LOG_ERR, c->log, err, "upstream send error");
				return NGX_ERROR;
			}
			if(n>0){
				b->pos += n;
				if (n != size) {
					ngx_log_error(NGX_LOG_ERR, c->log, err, "send error: data size:%zd, send size:%d",size,n);
					n = 0;
					goto cache;
				}
			}
			
			if (b->pos == b->last) {
				b->pos = b->start;
				b->last = b->start;
			}
		}
	}
	
	if(len <= 0)
		return NGX_OK;
	
	//printf("%s, %zd\n",data,len);
	
	if(c->write->ready){
		n = c->send(c, data, len);
		err = ngx_socket_errno;

		ngx_log_debug2(NGX_LOG_DEBUG_TCP, c->log, 0,
					   "xmpp upstream handler send:%d, %s", n,data);

		if (n == (size_t)NGX_ERROR) {
			ngx_log_error(NGX_LOG_ERR, c->log, err, "upstream send error");
			return NGX_ERROR;
		}
		if(n>0){
			if (n != len) {
				ngx_log_error(NGX_LOG_ERR, c->log, err, "send error: data size:%zd, send size:%d",len,n);
				goto cache;
			}
			return NGX_OK;
		}
	}
	
	n = 0;
	
cache:	
	
	size = len-n;
	if(size <= 0) return NGX_OK;
	
	if(b->end - b->last < size){
		ngx_log_error(NGX_LOG_ERR, c->log, err, "cache error: data size:%zd, buff size:%d",size,(b->end - b->last));
		return NGX_ERROR;
	}
	
	ngx_copy(b->last,data+n,size);
	b->last += size;
	
	if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
		return NGX_ERROR;
	}
	
	return NGX_AGAIN;
}
