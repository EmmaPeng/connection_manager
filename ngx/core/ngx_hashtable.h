/*
 * =====================================================================================
 *
 *       Filename:  ngx_hashtable.h
 *
 *    Description:  关于本程序：为了避免堆栈内存的释放不可区分导致的错误，这里要求所有name和key都必须是内pool存,该hash表的默认hash算法同java的hash函数，所以增长因子也是hash的0.75；可通过hash函数指针赋值方式定义算法
 *
 *        Version:  1.0
 *        Created:  02/27/2014 01:09:25 PM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  Humphery yu (), humphery.yu@gmail.com
 *   Organization:  
 *
 * =====================================================================================
 */


#ifndef _NGX_HASHTABLE_H_INCLUDED_
#define _NGX_HASHTABLE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <stdlib.h>

typedef ngx_uint_t (*ngx_hashtable_hash_pt) (u_char *data, size_t len);
typedef struct ngx_hashtable_elt_s ngx_hashtable_elt_t;

struct ngx_hashtable_elt_s{ //散列表结点类型
	ngx_str_t        	key;
    ngx_uint_t       	key_hash;
	void 				*value; //此类依赖于应用
	ngx_hashtable_elt_t *next;//第一个表的连表指针
	ngx_hashtable_elt_t *pt;//单独的第二个hashindex项
};

typedef struct{
    unsigned int 		size;
    unsigned int 		current;
	ngx_hashtable_hash_pt   	hash;
	ngx_pool_t       	*pool;
    ngx_hashtable_elt_t buckets[1];
} ngx_hashtable_t;



ngx_hashtable_t *ngx_hashtable_create(ngx_pool_t *poll,ngx_uint_t nelts);
void * ngx_hashtable_get(ngx_hashtable_t *ht,u_char *name, size_t len);
void ngx_hashtable_set(ngx_hashtable_t **hto,u_char *name, size_t len,void *value);
void ngx_hashtable_remove(ngx_hashtable_t *ht,u_char * name,size_t len);
ngx_uint_t ngx_hashtable_containkey(ngx_hashtable_t *hto,u_char * name,size_t len);
void ngx_hashtable_dump(ngx_hashtable_t *ht);


#endif

