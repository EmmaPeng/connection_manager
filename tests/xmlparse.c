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

int xml_pre_offset;
int xml_pre_index;
XML_Parser parser;
int isroute;
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
  int *depthPtr = (int *)userData;
  /*
  for (i = 0; i < *depthPtr; i++)
    putchar('\t');
  puts(name);
  */
  if(*depthPtr == 1){
	  if(memcmp("route",name,5) == 0){
		  isroute=1;
		  printf("%s\n","<route__ext>");
		  xml_pre_index=0;
	  }else{
		isroute=0;
	  }
  }else if(*depthPtr == 2){
	  if(isroute == 1){
		  if(xml_pre_index ==0){
			xml_pre_index = XML_GetCurrentByteIndex(parser);
			*depthPtr += 1;
			return;
		  }
		  int 	offset,size,index;
		  index = XML_GetCurrentByteIndex(parser);
		  char *str=XML_GetInputContext(parser, &offset, &size);
		  size = index - xml_pre_index;
		  char tmp[size+1];
		  memcpy(tmp,str+(offset-size),size);
		  tmp[size] = '\0';
		  printf("x. %s",tmp);
		  xml_pre_index = index;
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
	  xml_pre_index = XML_GetCurrentByteIndex(parser);
  }else if(*depthPtr > 2){
	  if(isroute == 1){
		  int 	offset,size,index;
		  index = XML_GetCurrentByteIndex(parser);
		  char *str=XML_GetInputContext(parser, &offset, &size);
		  size = index - xml_pre_index;
		 char tmp[size+1];
		 memcpy(tmp,str+(offset-size),size);
		 tmp[size] = '\0';
		 printf(", %s",tmp);
		  xml_pre_index = index;
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
	  }
  }
  *depthPtr += 1;
}

static void XMLCALL
endElement(void *userData, const char *name)
{
  int *depthPtr = (int *)userData;
  *depthPtr -= 1;
  if(*depthPtr == 1){
	  if(isroute == 1){
		  int 	offset,size,index;
		  index = XML_GetCurrentByteIndex(parser);
		  char *str=XML_GetInputContext(parser, &offset, &size);
		  size = index - xml_pre_index;
		  char tmp[size+1];
		  memcpy(tmp,str+(offset-size),size);
		  tmp[size] = '\0';
		  printf("$end$. %s $end$",tmp);
		  xml_pre_index = index;
		  
	  }
	  //XML_ParserReset(parser,0);
  }else if(*depthPtr == 2){
	  if(isroute == 1){
		  int 	offset,size,index;
		  index = XML_GetCurrentByteIndex(parser);
		  char *str=XML_GetInputContext(parser, &offset, &size);
		  size = index - xml_pre_index;
		  char tmp[size+1];
		  memcpy(tmp,str+(offset-size),size);
		  tmp[size] = '\0';
		  printf("$2end$. %s $2end$",tmp);
		  xml_pre_index = index;
		  
	  }
	  //XML_ParserReset(parser,0);
  }
}

int
main(int argc, char *argv[])
{
  char buf[BUFSIZ];
  parser = XML_ParserCreate(NULL);
  int done,i=0,len;
  int depth = 0;
  XML_SetUserData(parser, &depth);
  XML_SetElementHandler(parser, startElement, endElement);
  
  FILE *fp;
  fp = fopen ( "./demo.xml" , "rb" );
  if (fp == NULL) {fputs ("File error\n",stderr); exit (1);}
  
  fseek (fp , 0 , SEEK_END);
  int lSize = ftell (fp);
  rewind (fp);

  // allocate memory to contain the whole file:
  char *buffer = (char*) malloc (sizeof(char)*lSize);
  if (buffer == NULL) {fputs ("Memory error",stderr); exit (2);}
  
  int result = fread (buffer,1,lSize,fp);
  if (result != lSize) {fputs ("Reading error",stderr); exit (3);}
  
  printf("BUFSIZ: %d, filesize: %d,\n",BUFSIZ,lSize);
  len = 100;
  do {
	if(i+len>=lSize)len=lSize-i;
    if (XML_Parse(parser, buffer+i, len, 0) == XML_STATUS_ERROR) {
      fprintf(stderr,
              "%s at line %" XML_FMT_INT_MOD "u\n",
              XML_ErrorString(XML_GetErrorCode(parser)),
              XML_GetCurrentLineNumber(parser));
	  printf("%s\n",buffer+i);
      return 1;
    }
	if(i+len>=lSize)break;
	i+=len;
  } while (1);
  XML_ParserFree(parser);
  fclose (fp);
  free (buffer);
  return 0;
}
