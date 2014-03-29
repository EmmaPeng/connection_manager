#!/bin/sh

 find . \( -path ./tests/ -o -path exts/nginx_tcp_proxy_module/vitest/ragel \)  -prune -o -name *.[h,c,cpp] > cscope.files
gtags
cscope -Rq -i cscope.files

