#功能设计
用户请求web服务，基于用户的访问时间，浏览器ua信息等等给用户生成一个唯一id，记录到nginx的变量里，然后可以加入到nginx的log_format中，记录到用户每条访问日志，然后把生成的唯一id传回给用户端浏览器，写入cookie，这样用户下次再来访问的话就用cookie中已经保存的唯一id计入log中。

#如何使用
在nginx的源码目录中执行configure::

./configure --prefix=/usr/local/nginx/ --add-module=path-to-ngx_logid-folder

然后configure会找到这个目录下的config，将模块编译进nginx中，然后就可以使用了。

在配置文件中使用的示例::

    log_format  main  '$remote_addr - $remote_user [$time_local] "$request" '
                      '$status $body_bytes_sent "$http_referer" "$logid"'
                      '"$http_user_agent" "$http_x_forwarded_for"';

    server {
        listen       9999;
        server_name  www.logid.com;
        access_log  logs/logid.access.log  main;
        error_log  logs/logid.error.log  debug;
        logid on; 
        logid_cookie on; 
        logid_cookie_name "logid";
        logid_cookie_domain "*.logid.com";
        logid_cookie_path "/";
        logid_cookie_expire 1d;
        location / { 
            root   html;
            index  index.html index.htm;
        }   
    }

