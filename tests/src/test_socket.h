#ifndef _NGX_TEST_SOCKET_H_INCLUDED_
#define _NGX_TEST_SOCKET_H_INCLUDED_


//typedef u_char u_char;

typedef struct test_connection_s test_connection_t;

typedef int (*hand_pt)(test_connection_t*);

struct test_connection_s {
	int fd;
	hand_pt hand;
	size_t buf_size;
	struct epoll_event *ev;
	u_char *buf;
	void	*data;
	int current;
	unsigned         eof:1;
};

//#ifdef __cplusplus
//extern "C"{
//#endif

ssize_t test_unix_recv(test_connection_t *c, u_char *buf, size_t size);

ssize_t test_unix_send(test_connection_t *c, u_char *buf, size_t size);
//#ifdef __cplusplus
//}
//#endif

#endif
