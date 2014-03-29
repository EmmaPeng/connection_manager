/*
 * =====================================================================================
 *
 *       Filename:  ngx_hashtable.c
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

#include <ngx_hashtable.h>

static ngx_hashtable_t *ngx_hashtable_expend(ngx_hashtable_t **hto);
static ngx_uint_t ngx_hashtable_default_hash(u_char *name, size_t len);
/*
*功能：指定大小的新哈希表
*参数：nelts：用给定的长度建立一个hashtable表
*返回：成功与否
*/
ngx_hashtable_t *ngx_hashtable_create(ngx_pool_t *pool,ngx_uint_t nelts){
	if (pool == NULL) {
		return NULL;
	}

	ngx_hashtable_t *ht=(ngx_hashtable_t *)ngx_pcalloc(pool, nelts*(sizeof(ngx_hashtable_elt_t))+sizeof(ngx_hashtable_t));
	if (ht == NULL) {
		return NULL;
	}
	ht->pool=pool;
    ht->size=nelts;
    ht->current=0;
	ht->hash=ngx_hashtable_default_hash;
    return ht;

}


/*
*功能：取得给定key的值
*参数： ht：hash表指针 name：名称字符串
*返回：如果不存在就返回空
*/
void * ngx_hashtable_get(ngx_hashtable_t *ht,u_char *name, size_t len){
	    ngx_uint_t       i;
    ngx_hashtable_elt_t  *elt;

	ngx_uint_t hash=ht->hash(name,len);

    elt = ht->buckets[hash % ht->size].pt;

    if (elt) {
		while (1) {
			if (len != (size_t)elt->key.len){
				goto next;
			}

			for (i = 0; i < len; i++){
				if (name[i] != elt->key.data[i]){
					goto next;
				}
			}

			return elt->value;

		next:
			if(elt->next)
				elt = elt->next;
			else break;
		}
	}
    return NULL;

}

/*
*功能：设置一个项，不确定该项是否已经存在，如果存在就将它覆盖
*参数： ht：hash表指针地址 key：名称 value：值
*返回：void
*/
void ngx_hashtable_set(ngx_hashtable_t **hto,u_char *name, size_t len,void *value)
{
	if(len==0)return;
	ngx_uint_t       i;
    ngx_hashtable_t *ht=*hto;
    if((ht->size*75)<(ht->current*100))/**大于边界0.75就扩展*/ {
        ht=ngx_hashtable_expend(hto);
        *hto=ht;
    }

	ngx_hashtable_elt_t  *elt;

	ngx_uint_t hash=ht->hash(name,len);
	ngx_uint_t index=hash % ht->size;

    elt = ht->buckets[index].pt;

    if(!elt){
        elt=ht->buckets[index].pt=&ht->buckets[ht->current];
    }else {
          
        while(elt){
			if (len != elt->key.len) {
				goto next;
			}

			for (i = 0; i < len; i++) {
				if (name[i] != elt->key.data[i]) {
					goto next;
				}
			}

			elt->value=value;
			return;

		next:
            if(elt->next)
                elt=elt->next;
            else
                break;
        }
        elt->next=&ht->buckets[ht->current];
        elt=elt->next;
        elt->next=NULL;
        
    }

	
    elt->key.data=name;
	elt->key.len=len;
	elt->key_hash=hash;
    elt->value=value;
    ht->current++;
}
/*
*功能：新增一个项，可能会导致重复，但速度较快
*参数： ht：hash表指针地址 key：名称 value：值
*返回：void
*/
void ngx_hashtable_add(ngx_hashtable_t **hto,u_char *name, size_t len,void *value)
{
    ngx_hashtable_t   *ht=*hto;
    if((ht->size*75)<(ht->current*100)){
        ht=ngx_hashtable_expend(hto);
        *hto=ht;
    }
    ngx_uint_t hash=ht->hash(name,len);
    ngx_uint_t index=hash%ht->size;
    ngx_hashtable_elt_t *elt;
	
	elt=ht->buckets[index].pt;
	
    if(elt)
    {
        
        while(elt->next)
            elt=elt->next;
        elt->next=&ht->buckets[ht->current];
        elt=elt->next;
        elt->next=NULL;
    }
    else
        elt=ht->buckets[index].pt=&ht->buckets[ht->current];
	
	elt->key.data=name;
	elt->key.len=len;
	elt->key_hash=hash;
    elt->value=value;
	
    ht->current++;
}

/*
*功能：移出指定项
*参数：ht：hash表指针 key：要移出的名称
*返回：void
*/
void ngx_hashtable_remove(ngx_hashtable_t *ht,u_char * name,size_t len){
	ngx_uint_t       i;
    ngx_hashtable_elt_t  *elt,*elt1;

	ngx_uint_t hash=ht->hash(name,len);
	ngx_uint_t index=hash % ht->size;
    elt = ht->buckets[index].pt;

    if (elt) {
		elt1=elt;
		while(elt) {
			
			if (len != elt->key.len) {
				goto next;
			}

			for (i = 0; i < len; i++) {
				if (name[i] != elt->key.data[i]) {
					goto next;
				}
			}
		
			elt->key.data=NULL;
			elt->key.len=0;
			elt->key_hash=0;
			elt->value=NULL;
			if(elt==ht->buckets[index].pt)
				ht->buckets[index].pt=NULL;
			else
				elt1->next=elt->next;
			return;
			
		next:
			elt1=elt;
			elt=elt->next;
		}
	}
}
/*
*功能：是否包含指定项
*参数：ht：hash表指针 name：名称
*返回：void
*/
ngx_uint_t ngx_hashtable_containkey(ngx_hashtable_t *ht,u_char * name,size_t len)
{
	ngx_uint_t       i;
	ngx_hashtable_elt_t  *elt;

	ngx_uint_t hash=ht->hash(name,len);

    elt = ht->buckets[hash % ht->size].pt;

    while(elt) {
		if (len != (size_t) elt->key.len){
			goto next;
		}

		for (i = 0; i < len; i++) {
			if (name[i] != elt->key.data[i]){
				goto next;
			}
		}
        return 1;
	next:
        elt=elt->next;
    }
    return 0;
}

/**拷贝两个hash表*/
static void ngx_hashtable_copy(ngx_hashtable_t **ht,ngx_hashtable_t *To)
{
    ngx_uint_t       i;

    ngx_hashtable_elt_t * nodeT=To->buckets;
    for(i=0;i<To->size;i++)
    {
        if(nodeT[i].key.len)
        {
			ngx_hashtable_add(ht,nodeT[i].key.data,nodeT[i].key.len,nodeT[i].value);
        }
    }
}
/*
*功能：扩展现有的表
*参数：ht；hash表指针地址
*返回：hash表
*/
static ngx_hashtable_t *ngx_hashtable_expend(ngx_hashtable_t **hto)
{
    ngx_hashtable_t *ht=*hto;
    ngx_uint_t length =(ht->current) * 2 + 1;
    ngx_hashtable_t *hs=ngx_hashtable_create(ht->pool,length);
    ngx_hashtable_copy(&hs, ht);
    
	ngx_pfree(hs->pool,*hto);
    *hto=hs;
    return hs;
}
/*
*功能：打印hash表
*参数：ht：hash表指针
*返回：void
*/
void ngx_hashtable_dump(ngx_hashtable_t *ht)
{
    ngx_hashtable_elt_t *node=ht->buckets,*node1;
    ngx_uint_t       i,j;
    for(i=0;i<ht->size;i++) {
            //if(node[i].key)
            printf("Buckets：%d=> Key:%s, Value:%p,Next:%p,Object:%p\n",i, node[i].key.data,node[i].value,node[i].pt,node[i]);
            node1=node[i].pt;
			j=0;
            while(node1)
            {
             printf("\t\tElt: %d=> Key:%s, Value:%p, Next:%p, Object-pt:%p\n",j++, node1->key.data,node1->value,node1->pt,node1);
             node1=node1->next;
            }
        }
}

/** 
*功能：仿java语言的hash算法
*参数：name：需要计算的key名称
*返回：ngx_uint_t hash值
*/
static ngx_uint_t ngx_hashtable_hash4java(u_char *name, size_t len){
	ngx_uint_t hash;
    u_char *p;
    for(hash=0, p = name; *p ; p++)
        hash = 31 * hash + *p;
    hash=hash & 0x7FFFFFFF;
    return hash;
}

/** 
*功能：默认hash算法
*参数：name：需要计算的key名称
*返回：ngx_uint_t hash值
*/
static ngx_uint_t ngx_hashtable_default_hash(u_char *name, size_t nKeyLength)
{
	u_char *arKey=name;
    register ngx_uint_t hash = 5381;
    for (; nKeyLength >= 8; nKeyLength -= 8) {
        hash = ((hash << 5) + hash) + *arKey++;
        hash = ((hash << 5) + hash) + *arKey++;
        hash = ((hash << 5) + hash) + *arKey++;
        hash = ((hash << 5) + hash) + *arKey++;
        hash = ((hash << 5) + hash) + *arKey++;
        hash = ((hash << 5) + hash) + *arKey++;
        hash = ((hash << 5) + hash) + *arKey++;
        hash = ((hash << 5) + hash) + *arKey++;
    }
    switch (nKeyLength) {
        case 7: hash = ((hash << 5) + hash) + *arKey++; /* fallthrough... */
        case 6: hash = ((hash << 5) + hash) + *arKey++; /* fallthrough... */
        case 5: hash = ((hash << 5) + hash) + *arKey++; /* fallthrough... */
        case 4: hash = ((hash << 5) + hash) + *arKey++; /* fallthrough... */
        case 3: hash = ((hash << 5) + hash) + *arKey++; /* fallthrough... */
        case 2: hash = ((hash << 5) + hash) + *arKey++; /* fallthrough... */
        case 1: hash = ((hash << 5) + hash) + *arKey++; break;
        case 0: break;
        default:
			break;
    }
    return hash;
}

void ngx_hashtable_test(ngx_pool_t *pool){
	char x;
	int datanum=10000000,count=0,randnum;
	
	char (*strRand)[31]=(char(*)[31])malloc(datanum*31);
	//char strRand[datanum][11];
	for(int i=0;i<datanum;i++){
		for(int k=0;k<30;k++){
			randnum=rand();
			randnum==0?1:randnum;
			if(randnum%2)
				x = randnum%26+'a';
			else 
				x = randnum%26+'A';
			strRand[i][k]=x;
		}
	}
	
	ngx_hashtable_t *ht = ngx_hashtable_create(pool,100000);
	
	struct timeval tpstart,tpend;
	float timeuse;

	gettimeofday(&tpstart,NULL);
	
	printf("set ... \n");
	//set
	for(int i=0;i<datanum;i++){
		ngx_hashtable_set(&ht,strRand[i],strlen(strRand[i]),strRand[i]);
	}
	//char *value_ = ngx_hashtable_get(ht,testKey,strlen(testKey));

	//ngx_hashtable_dump(ht);
	
	
	//get
	for(int i=0;i<datanum;i++){
		char *t=(char*)ngx_hashtable_get(ht,strRand[i],strlen(strRand[i]));
		if(t)
			count++;//printf("%s = %s\n",testKeyTmp,t);
	}
	printf("get ... %d\n",count);
	printf("delete ... \n");
	//delete
	for(int i=0;i<datanum;i++){
		ngx_hashtable_remove(ht,strRand[i],strlen(strRand[i]));
	}
	printf("get ... \n");
	for(int i=0;i<datanum;i++){
		char *t=(char*)ngx_hashtable_get(ht,strRand[i],strlen(strRand[i]));
		if(t)
			printf("%s = %s\n",strRand[i],t);
	}
	
	gettimeofday(&tpend,NULL);
	timeuse=1000000*(tpend.tv_sec-tpstart.tv_sec)+tpend.tv_usec-tpstart.tv_usec;
	timeuse/=1000000;
	printf("Used Time:%f\n",timeuse);
}
