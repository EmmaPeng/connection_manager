/* This is simple demonstration of how to use expat. This program
   reads an XML document from standard input and writes a line with
   the name of each element to standard output indenting child
   elements by one tab stop more than their parent element.
   It must be used with Expat compiled for UTF-8 output.
*/
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_hashtable.h>
#include <stdio.h>
#include "expat.h"
#include <test_socket.h>

#if defined(__amigaos__) && defined(__USE_INLINE__)
#include <proto/expat.h>
#endif

#ifdef XML_LARGE_SIZE
#if defined(XML_USE_MSC_EXTENSIONS) && _MSC_VER < 1400
#define XML_FMT_INT_MOD "I64"
#else
#define XML_FMT_INT_MOD "ll"
#endif
#else
#define XML_FMT_INT_MOD "l"
#endif

ngx_cycle_t *cycle;

ngx_cycle_t *init_nginx();
int init_hand(test_connection_t *c){return 0;}

typedef struct{
	//int xml_pre_offset;
	int xml_pre_index;
	int depth;
	int isroute;
	XML_Parser parser;
	ngx_buf_t  *wbuffer;
	ngx_pool_t *pool;
}parse_ctx_t;


/*
void *malloc_fcn(size_t size);
void *realloc_fcn(void *ptr, size_t size);
void free_fcn(void *ptr);

static XML_Memory_Handling_Suite memory_handler = {
	malloc_fcn,
	realloc_fcn,
	free_fcn
};
*/

static void XMLCALL
startElement(void *userData, const char *name, const char **atts)
{
  int i;
  ngx_buf_t *b;
  parse_ctx_t *ctx = (parse_ctx_t*)userData;
  b = ctx->wbuffer;
  /*
  for (i = 0; i < *depthPtr; i++)
    putchar('\t');
  puts(name);
  */
  if(ctx->depth == 1){
	  if(memcmp("route",name,5) == 0){
		  int 	offset,size;
		  ctx->isroute=1;
		  //printf("%s\n","<route__ext>");
		  ctx->xml_pre_index=0;
		  char *str=XML_GetInputContext(ctx->parser, &offset, &size);
		  //ctx->xml_pre_offset=offset;
		  
		  
	  }else{
		ctx->isroute=0;
	  }
  }else if(ctx->depth >= 2){
	  if(ctx->isroute == 1){
		  int 	offset,size,index;
		  index = XML_GetCurrentByteIndex(ctx->parser);
		  if(ctx->xml_pre_index >0){
			  char *str=XML_GetInputContext(ctx->parser, &offset, &size);
			  size = index - ctx->xml_pre_index;

			  ngx_copy(b->last, str+(offset-size),size);
			  b->last += size;
		  }
		  ctx->xml_pre_index = index;
		  //ctx->xml_pre_offset=offset;
		  //size=offset - ctx->xml_pre_offset;
		  // printf("offset: %d, ctx->xml_pre_offset: %d,index: %d, strlen(el): %s, size: %d, data:\n",offset , xml_pre_offset,index,name,size);
		  /*
		  size = index - xml_pre_offset;
		  if(size > 1024){
			str[size]='\0';
			printf("%s",str+ xml_pre_offset);
			xml_pre_offset=index;
		  }
		  */
	  }else
	  ctx->xml_pre_index = XML_GetCurrentByteIndex(ctx->parser);
  }
  ctx->depth += 1;
}

static void XMLCALL
endElement(void *userData, const char *name)
{
	ngx_buf_t *b;
	parse_ctx_t *ctx = (parse_ctx_t*)userData;
	b = ctx->wbuffer;
  ctx->depth -= 1;
  if(ctx->depth == 1){
	  if(ctx->isroute == 1){
		  int 	offset,size,index;
		  index = XML_GetCurrentByteIndex(ctx->parser);
		  char *str=XML_GetInputContext(ctx->parser, &offset, &size);
		  size = index - ctx->xml_pre_index;
		  
		  ngx_copy(b->last, str+(offset-size),size);
		  b->last[size] = '\0';
		  b->last += size;
		  
		  printf(" offset=%s\n",str+offset);
		  //printf("pre index=%d, index=%d, pre offset=%d, offset=%d, size=%d, str=%s\n",ctx->xml_pre_index,ctx->xml_pre_offset,index,offset,size,str);
		  printf("************** \n%s\n************** \n",b->pos);
		  b->last = b->pos = b->start;
		  
		  ctx->xml_pre_index = index;
		  //ctx->xml_pre_offset=offset;
	  }
	  //XML_ParserReset(parser,0);
  }else if(ctx->depth >= 2){
	  if(ctx->isroute == 1){
		  int 	offset,size,index;
		  index = XML_GetCurrentByteIndex(ctx->parser);
		  char *str=XML_GetInputContext(ctx->parser, &offset, &size);
		  size = index - ctx->xml_pre_index;
		  ngx_copy(b->last, str+(offset-size),size);
		  b->last += size;
		  //printf(" offset=%s\n",str+offset);
		  ctx->xml_pre_index = index;
		  //ctx->xml_pre_offset=offset;
	  }
	  //XML_ParserReset(parser,0);
  }
}

int readfile(char **buffer,int* blen){
	FILE *fp;
	fp = fopen ( "./demo.xml" , "rb" );
	if (fp == NULL) {fputs ("File error\n",stderr); exit (1);}
	
	fseek (fp , 0 , SEEK_END);
	int buffer_len = ftell (fp);
	rewind (fp);

	// allocate memory to contain the whole file:
	*buffer = (char*) malloc (sizeof(char)*buffer_len);
	if (*buffer == NULL) {fputs ("Memory error",stderr); exit (2);}
	
	int result = fread (*buffer,1,buffer_len,fp);
	if (result != buffer_len) {fputs ("Reading error",stderr); exit (3);}
	
	printf("BUFSIZ: %d, filesize: %d,\n",BUFSIZ,buffer_len);
	fclose (fp);
	*blen = buffer_len;
	return 0;
}
int
main(int argc, char *argv[])
{
  char *buffer;
  int buffer_len;
  int done,i=0,len;
  parse_ctx_t ctx;
  cycle = init_nginx();
  ctx.pool = cycle->pool;
  
  ctx.parser = XML_ParserCreate(NULL);
  ctx.depth = 0;
  XML_SetUserData(ctx.parser, &ctx);
  XML_SetElementHandler(ctx.parser, startElement, endElement);
  
  ctx.wbuffer = ngx_create_temp_buf(ctx.pool, 40960);
  
  readfile(&buffer,&buffer_len);

  len = 100;
  do {
	if(i+len>=buffer_len)len=buffer_len-i;
    if (XML_Parse(ctx.parser, buffer+i, len, 0) == XML_STATUS_ERROR) {
      fprintf(stderr,
              "%s at line %" XML_FMT_INT_MOD "u\n",
              XML_ErrorString(XML_GetErrorCode(ctx.parser)),
              XML_GetCurrentLineNumber(ctx.parser));
	  printf("%s\n",buffer+i);
      return 1;
    }
	if(i+len>=buffer_len)break;
	i+=len;
  } while (1);
  XML_ParserFree(ctx.parser);
  
  free (buffer);
  return 0;
}
