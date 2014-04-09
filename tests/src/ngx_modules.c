
#include <ngx_config.h>
#include <ngx_core.h>



extern ngx_module_t  ngx_core_module;
extern ngx_module_t  ngx_errlog_module;
extern ngx_module_t  ngx_conf_module;
extern ngx_module_t  ngx_dso_module;
extern ngx_module_t  ngx_syslog_module;
extern ngx_module_t  ngx_events_module;
extern ngx_module_t  ngx_event_core_module;
extern ngx_module_t  ngx_epoll_module;
extern ngx_module_t  ngx_procs_module;
extern ngx_module_t  ngx_proc_core_module;
extern ngx_module_t  ngx_regex_module;
extern ngx_module_t  ngx_test_proxy_module;

ngx_module_t *ngx_modules[] = {
    &ngx_core_module,
    &ngx_errlog_module,
    &ngx_conf_module,
    &ngx_syslog_module,
    &ngx_events_module,
    &ngx_event_core_module,
    &ngx_epoll_module,
    &ngx_procs_module,
    &ngx_proc_core_module,
    &ngx_regex_module,
	&ngx_test_proxy_module,
    NULL
};

u_char *ngx_module_names[] = {
    (u_char *) "ngx_core_module",
    (u_char *) "ngx_errlog_module",
    (u_char *) "ngx_conf_module",
    (u_char *) "ngx_syslog_module",
    (u_char *) "ngx_events_module",
    (u_char *) "ngx_event_core_module",
    (u_char *) "ngx_epoll_module",
    (u_char *) "ngx_procs_module",
    (u_char *) "ngx_proc_core_module",
    (u_char *) "ngx_regex_module",
	(u_char *) "ngx_test_proxy_module",
    NULL
};


const char *ngx_all_module_names[] = {
    "ngx_core_module",
    "ngx_errlog_module",
    "ngx_conf_module",
    "ngx_events_module",
    "ngx_event_core_module",
    "ngx_rtsig_module",
    "ngx_epoll_module",
    "ngx_select_module",
    "ngx_poll_module",
    "ngx_openssl_module",
    "ngx_regex_module",
    "ngx_test_proxy_module",
    NULL
};


const char *ngx_dso_abi_all_tags[] = {
    "with-debug",
    "with-ipv6",
    "with-syslog",
    NULL
};

