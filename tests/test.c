/*
 * =====================================================================================
 *
 *       Filename:  server.c
 *
 *    Description:  tcp server
 *
 *        Version:  1.0
 *        Created:  01/20/2014 04:33:03 AM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  Humphery yu (), humphery.yu@gmail.com
 *   Organization:  
 *
 * =====================================================================================
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_hashtable.h>
#include <test_socket.h>
#include <ngx_sha1.h>
#include <ngx_md5.h>
#include <ngx_crypt.h>



#define MAXLINE 5
#define OPEN_MAX 100
#define LISTENQ 20
#define SERV_PORT 5000
#define INFTIM 1000
ngx_cycle_t *cycle;

ngx_cycle_t *init_nginx();
int init_hand(test_connection_t *c){return 0;}

//字节流转换为十六进制字符串
void ByteToHexStr(const unsigned char* source, char* dest, int sourceLen)
{
    short i;
    unsigned char highByte, lowByte;

    for (i = 0; i < sourceLen; i++)
    {
        highByte = source[i] >> 4;
        lowByte = source[i] & 0x0f ;

        highByte += 0x30;

        if (highByte > 0x39)
                dest[i * 2] = highByte + 0x07;
        else
                dest[i * 2] = highByte;

        lowByte += 0x30;
        if (lowByte > 0x39)
            dest[i * 2 + 1] = lowByte + 0x07;
        else
            dest[i * 2 + 1] = lowByte;
    }
    return ;
}

//字节流转换为十六进制字符串的另一种实现方式

void Hex2Str( const char *sSrc,  char *sDest, int nSrcLen )
{
    int  i;
    char szTmp[3];


    for( i = 0; i < nSrcLen; i++ )
    {
        sprintf( szTmp, "%02X", (unsigned char) sSrc[i] );
        memcpy( &sDest[i * 2], szTmp, 2 );
    }
    return ;
}

//十六进制字符串转换为字节流
void HexStrToByte(const char* source, unsigned char* dest, int sourceLen)
{
    short i;
    unsigned char highByte, lowByte;
    
    for (i = 0; i < sourceLen; i += 2)
    {
        highByte = toupper(source[i]);
        lowByte  = toupper(source[i + 1]);


        if (highByte > 0x39)
            highByte -= 0x37;
        else
            highByte -= 0x30;


        if (lowByte > 0x39)
            lowByte -= 0x37;
        else
            lowByte -= 0x30;


        dest[i / 2] = (highByte << 4) | lowByte;
    }
    return ;
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

int m(){
	MD5_CTX ctx;
	ngx_str_t xml_streamid;
	ngx_str_set(&xml_streamid,(u_char*)"d5606bc5");
	
	unsigned char *data=xml_streamid.data;
	unsigned char md[16];
	char buf[33]={'\0'};

	MD5_Init(&ctx);
	MD5_Update(&ctx,data,xml_streamid.len);
	MD5_Final(md,&ctx);
	ngx_hex_dump(buf,md,16);
	/*
	for( i=0; i<16; i++ ){
		sprintf(tmp,"%02X",md[i]);
		strcat(buf,tmp);
	}
	*/
	printf("%s\n",buf);
	return 0;
}

void md5(){
	int rc;
    //lock_guard<mutex> l(lock_);
	ngx_str_t encrypted;
	//encrypted.data = b->last;
	

	ngx_str_t xml_streamid;
	
	xml_streamid.data = (u_char*)"d5606bc5";
	xml_streamid.len = ngx_strlen(xml_streamid.data);
	
	u_char  digest[16];
	ngx_md5_t  md5;
	
	ngx_md5_init(&md5);
    ngx_md5_update(&md5, xml_streamid.data, xml_streamid.len);
	ngx_md5_final(digest, &md5);
	int len = 2 * sizeof(digest);
	encrypted.data = (u_char*)ngx_pnalloc(cycle->pool, len);

	
	ngx_hex_dump(encrypted.data,digest,16);
	
	/*
	 rc = ngx_crypt_sha(cycle->pool, xml_streamid.data, xml_streamid.len,
			&encrypted);
	*/
	
	printf("rc: %d streamid: \"%s\" encrypted: \"%s\" \n",
	rc, xml_streamid.data, encrypted.data);
}
//mutex lock_;
int main(int argc, char* argv[])
{
	cycle = init_nginx();
	
	ngx_str_t xml_streamid;
	ngx_str_t encrypted;
	ngx_str_t 	key;
	key.data = "789";
	key.len	= 3;
	int rc;
	
	xml_streamid.data = (u_char*)"4b1b474d";
	xml_streamid.len = ngx_strlen(xml_streamid.data);
	
	encrypted.len = 2 * SHA_DIGEST_LENGTH;///ngx_base64_encoded_length(decoded.len) + 1;
	u_char buf[encrypted.len+1];
	encrypted.data = buf;
	
	rc = ngx_crypt_sha(xml_streamid.data, xml_streamid.len,&key,
					   &encrypted);
	
	printf("rc: %d streamid: \"%s\" encrypted: \"%s\" \n",
		   rc, xml_streamid.data, encrypted.data);
	return 0;
}



