/************************************************************************/
02
/*函数名：Hashed
03
/*功  能：检测一个字符串是否被hash过
04
/*返回值：如果存在，返回位置；否则，返回-1
05
/************************************************************************/
06
unsigned long StringHash::Hashed(string lpszString) 
07
 
08
{  
09
    const unsigned long HASH_OFFSET = 0, HASH_A = 1, HASH_B = 2; 
10
    //不同的字符串三次hash还会碰撞的几率无限接近于不可能
11
    unsigned long nHash = HashString(lpszString, HASH_OFFSET); 
12
    unsigned long nHashA = HashString(lpszString, HASH_A); 
13
    unsigned long nHashB = HashString(lpszString, HASH_B); 
14
    unsigned long nHashStart = nHash % m_tablelength, 
15
    nHashPos = nHashStart; 
16
 
17
    while ( m_HashIndexTable[nHashPos].bExists) 
18
    {  
19
        if (m_HashIndexTable[nHashPos].nHashA == nHashA && m_HashIndexTable[nHashPos].nHashB == nHashB)  
20
            return nHashPos;  
21
        else  
22
            nHashPos = (nHashPos + 1) % m_tablelength; 
23
 
24
        if (nHashPos == nHashStart)  
25
            break;  
26
    } 
27
 
28
    return -1; //没有找到 
29
} 
30
 
31
/************************************************************************/
32
/*函数名：Hash
33
/*功  能：hash一个字符串
34
/*返回值：成功，返回true；失败，返回false
35
/************************************************************************/
36
bool StringHash::Hash(string lpszString)
37
{ 
38
    const unsigned long HASH_OFFSET = 0, HASH_A = 1, HASH_B = 2; 
39
    unsigned long nHash = HashString(lpszString, HASH_OFFSET); 
40
    unsigned long nHashA = HashString(lpszString, HASH_A); 
41
    unsigned long nHashB = HashString(lpszString, HASH_B); 
42
    unsigned long nHashStart = nHash % m_tablelength,
43
        nHashPos = nHashStart; 
44
        //你得自己保证此字符串没有被hash过，否则hash表中就会存在完全相同的元素
45
    while ( m_HashIndexTable[nHashPos].bExists) 
46
    {  
47
                //如果发生碰撞，就在相邻位置插入
48
        nHashPos = (nHashPos + 1) % m_tablelength; 
49
        if (nHashPos == nHashStart) //一个轮回 
50
        { 
51
            //hash表中没有空余的位置了,无法完成hash
52
            return false;  
53
        } 
54
    } 
55
    m_HashIndexTable[nHashPos].bExists = true; 
56
    m_HashIndexTable[nHashPos].nHashA = nHashA; 
57
    m_HashIndexTable[nHashPos].nHashB = nHashB; 
58
 
59
    return true; 
60
}
2. [文件] StringHash.h ~ 828B     下载(141)     
01
#pragma once
02
 
03
#define MAXTABLELEN 1024    // 默认哈希索引表大小
04
////////////////////////////////////////////////////////////////////////// 
05
// 哈希索引表定义 
06
typedef struct  _HASHTABLE
07
{ 
08
    long nHashA; 
09
    long nHashB; 
10
    bool bExists; 
11
}HASHTABLE, *PHASHTABLE ; 
12
 
13
class StringHash
14
{
15
public:
16
    StringHash(const long nTableLength = MAXTABLELEN);
17
    ~StringHash(void);
18
private: 
19
    unsigned long cryptTable[0x500]; 
20
    unsigned long m_tablelength;    // 哈希索引表长度 
21
    HASHTABLE *m_HashIndexTable;
22
private:
23
    void InitCryptTable();                                               // 对哈希索引表预处理
24
    unsigned long HashString(const string& lpszString, unsigned long dwHashType); // 求取哈希值     
25
public:
26
    bool Hash(string url);
27
    unsigned long Hashed(string url);    // 检测url是否被hash过
28
};
3. [文件] StringHash.cpp ~ 4KB     下载(132)     
001
#include "StdAfx.h"
002
#include "StringHash.h"
003
 
004
StringHash::StringHash(const long nTableLength /*= MAXTABLELEN*/)
005
{
006
    InitCryptTable(); 
007
    m_tablelength = nTableLength; 
008
    //初始化hash表
009
    m_HashIndexTable = new HASHTABLE[nTableLength]; 
010
    for ( int i = 0; i < nTableLength; i++ ) 
011
    { 
012
        m_HashIndexTable[i].nHashA = -1; 
013
        m_HashIndexTable[i].nHashB = -1; 
014
        m_HashIndexTable[i].bExists = false; 
015
    }         
016
}
017
 
018
StringHash::~StringHash(void)
019
{
020
    //清理内存
021
    if ( NULL != m_HashIndexTable ) 
022
    { 
023
        delete []m_HashIndexTable; 
024
        m_HashIndexTable = NULL; 
025
        m_tablelength = 0; 
026
    } 
027
}
028
 
029
/************************************************************************/
030
/*函数名：InitCryptTable
031
/*功  能：对哈希索引表预处理 
032
/*返回值：无
033
/************************************************************************/
034
void StringHash::InitCryptTable() 
035
{  
036
    unsigned long seed = 0x00100001, index1 = 0, index2 = 0, i; 
037
 
038
    for( index1 = 0; index1 < 0x100; index1++ ) 
039
    {  
040
        for( index2 = index1, i = 0; i < 5; i++, index2 += 0x100 ) 
041
        {  
042
            unsigned long temp1, temp2; 
043
            seed = (seed * 125 + 3) % 0x2AAAAB; 
044
            temp1 = (seed & 0xFFFF) << 0x10; 
045
            seed = (seed * 125 + 3) % 0x2AAAAB; 
046
            temp2 = (seed & 0xFFFF); 
047
            cryptTable[index2] = ( temp1 | temp2 );  
048
        }  
049
    }  
050
} 
051
 
052
/************************************************************************/
053
/*函数名：HashString
054
/*功  能：求取哈希值  
055
/*返回值：返回hash值
056
/************************************************************************/
057
unsigned long StringHash::HashString(const string& lpszString, unsigned long dwHashType) 
058
{  
059
    unsigned char *key = (unsigned char *)(const_cast<char*>(lpszString.c_str())); 
060
    unsigned long seed1 = 0x7FED7FED, seed2 = 0xEEEEEEEE; 
061
    int ch; 
062
 
063
    while(*key != 0) 
064
    {  
065
        ch = toupper(*key++); 
066
 
067
        seed1 = cryptTable[(dwHashType << 8) + ch] ^ (seed1 + seed2); 
068
        seed2 = ch + seed1 + seed2 + (seed2 << 5) + 3;  
069
    } 
070
    return seed1;  
071
} 
072
 
073
/************************************************************************/
074
/*函数名：Hashed
075
/*功  能：检测一个字符串是否被hash过
076
/*返回值：如果存在，返回位置；否则，返回-1
077
/************************************************************************/
078
unsigned long StringHash::Hashed(string lpszString) 
079
 
080
{  
081
    const unsigned long HASH_OFFSET = 0, HASH_A = 1, HASH_B = 2; 
082
    //不同的字符串三次hash还会碰撞的几率无限接近于不可能
083
    unsigned long nHash = HashString(lpszString, HASH_OFFSET); 
084
    unsigned long nHashA = HashString(lpszString, HASH_A); 
085
    unsigned long nHashB = HashString(lpszString, HASH_B); 
086
    unsigned long nHashStart = nHash % m_tablelength, 
087
    nHashPos = nHashStart; 
088
 
089
    while ( m_HashIndexTable[nHashPos].bExists) 
090
    {  
091
        if (m_HashIndexTable[nHashPos].nHashA == nHashA && m_HashIndexTable[nHashPos].nHashB == nHashB)  
092
            return nHashPos;  
093
        else  
094
            nHashPos = (nHashPos + 1) % m_tablelength; 
095
 
096
        if (nHashPos == nHashStart)  
097
            break;  
098
    } 
099
 
100
    return -1; //没有找到 
101
} 
102
 
103
/************************************************************************/
104
/*函数名：Hash
105
/*功  能：hash一个字符串
106
/*返回值：成功，返回true；失败，返回false
107
/************************************************************************/
108
bool StringHash::Hash(string lpszString)
109
{ 
110
    const unsigned long HASH_OFFSET = 0, HASH_A = 1, HASH_B = 2; 
111
    unsigned long nHash = HashString(lpszString, HASH_OFFSET); 
112
    unsigned long nHashA = HashString(lpszString, HASH_A); 
113
    unsigned long nHashB = HashString(lpszString, HASH_B); 
114
    unsigned long nHashStart = nHash % m_tablelength,
115
        nHashPos = nHashStart; 
116
 
117
    while ( m_HashIndexTable[nHashPos].bExists) 
118
    {  
119
        nHashPos = (nHashPos + 1) % m_tablelength; 
120
        if (nHashPos == nHashStart) //一个轮回 
121
        { 
122
            //hash表中没有空余的位置了,无法完成hash
123
            return false;  
124
        } 
125
    } 
126
    m_HashIndexTable[nHashPos].bExists = true; 
127
    m_HashIndexTable[nHashPos].nHashA = nHashA; 
128
    m_HashIndexTable[nHashPos].nHashB = nHashB; 
129
 
130
    return true; 
131
}
