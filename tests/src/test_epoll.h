#ifndef _NGX_EPOLL_H_INCLUDED_
#define _NGX_EPOLL_H_INCLUDED_

extern int epfd;
extern struct epoll_event  *event_list;
extern int      nevents;

int init_hand(test_connection_t *c);
void etnonblocking(int sock);
void test_process_events_and_timers(test_connection_t *lc);
ngx_int_t test_epoll_init(test_connection_t *c);
ngx_int_t test_epoll_add_connection(test_connection_t *c);

#endif

