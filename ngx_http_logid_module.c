#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_md5.h>

#define MD5_HASH_LEN 16
#define LOG_ID_LEN 32

typedef struct
{
    ngx_flag_t    enable;

    ngx_flag_t    cookie_enable;
    ngx_str_t     cookie_name;
    ngx_str_t     cookie_domain;
    ngx_str_t     cookie_path;
    time_t        cookie_expire_time;
} ngx_http_logid_conf_t;

static ngx_str_t ngx_http_logid = ngx_string("logid");

static ngx_int_t ngx_http_logid_init(ngx_conf_t *cf);

static ngx_str_t* ngx_http_logid_get_new_logid(ngx_http_request_t *r);
static void *ngx_http_logid_create_conf(ngx_conf_t *cf);
static char *ngx_http_logid_merge_conf(ngx_conf_t *cf, void *parent,
                                       void *child);
static ngx_int_t
ngx_logid_cookie_set(ngx_http_request_t *r, ngx_http_logid_conf_t *conf, ngx_str_t* value);
static ngx_int_t
ngx_http_logid_cookie_parse(ngx_http_request_t *r, ngx_str_t *value);


static ngx_command_t ngx_http_logid_commands[] =
{
    {
        ngx_string("logid"),
        NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG|NGX_HTTP_LIF_CONF|NGX_HTTP_SIF_CONF,
        ngx_conf_set_flag_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_logid_conf_t, enable),
        NULL
    },
    {
        ngx_string("logid_cookie"),
        NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG|NGX_HTTP_LIF_CONF|NGX_HTTP_SIF_CONF,
        ngx_conf_set_flag_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_logid_conf_t, cookie_enable),
        NULL
    },
    { ngx_string("logid_cookie_name"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_HTTP_SIF_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_logid_conf_t, cookie_name),
      NULL 
    },
    { ngx_string("logid_cookie_domain"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_HTTP_SIF_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_logid_conf_t, cookie_domain),
      NULL
    },
    { ngx_string("logid_cookie_path"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_HTTP_SIF_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_logid_conf_t, cookie_path),
      NULL
    },
    { ngx_string("logid_cookie_expire"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_HTTP_SIF_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_logid_conf_t, cookie_expire_time),
      NULL
    },
    ngx_null_command
};


static ngx_http_module_t ngx_http_logid_module_ctx =
{
    NULL,      /* preconfiguration */
    ngx_http_logid_init,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_logid_create_conf,        /* create location configration */
    ngx_http_logid_merge_conf          /* merge location configration */
};


ngx_module_t ngx_http_logid_module =
{
    NGX_MODULE_V1,
    &ngx_http_logid_module_ctx,        /* module context */
    ngx_http_logid_commands,           /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_http_output_header_filter_pt ngx_http_next_header_filter;

static ngx_int_t
ngx_http_logid_header_filter(ngx_http_request_t *r)
{
    ngx_http_logid_conf_t   *conf;
    ngx_str_t cookie_value;
    ngx_str_t* logid;
    ngx_http_variable_value_t* v;
    ngx_int_t key;
    u_char* src;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_logid_module);

    if(!conf->enable
        || !conf->cookie_enable
        || r != r->main
        || r->error_page
        || r->post_action)
    {
        return ngx_http_next_header_filter(r);
    }

    if (ngx_http_logid_cookie_parse(r, &cookie_value) == NGX_OK && cookie_value.len == LOG_ID_LEN)
    {
        return ngx_http_next_header_filter(r);
    }

    src = ngx_pnalloc(r->pool, ngx_http_logid.len);
    ngx_memcpy(src, ngx_http_logid.data, ngx_http_logid.len);
    key = ngx_hash_strlow(src, src, ngx_http_logid.len);

    v = ngx_http_get_variable(r, &ngx_http_logid, key);
    logid = ngx_pnalloc(r->pool, sizeof(ngx_str_t));
    logid->data = v->data;
    logid->len = v->len;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "get log id:%s", logid->data);

    if (logid->data == NULL || logid->len == 0)
    {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "get empty value");
        return ngx_http_next_header_filter(r);
    }

    if (ngx_logid_cookie_set(r, conf, logid) != NGX_OK)
    {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "cookie set error");
        return NGX_ERROR;
    }

    return ngx_http_next_header_filter(r);
}

static ngx_int_t
ngx_http_logid_set_variable(ngx_http_request_t *r,
     ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_logid_conf_t   *conf;
    ngx_str_t cookie_value;
    ngx_str_t* logid;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_logid_module);

    if(!conf->enable)
    {
        v->not_found = 1;
        return NGX_OK;
    }

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->len = LOG_ID_LEN;
    v->data = ngx_pnalloc(r->pool, LOG_ID_LEN);
    if (v->data == NULL) {
        return NGX_ERROR;
    }

    if (conf->cookie_enable)
    {
        if (ngx_http_logid_cookie_parse(r, &cookie_value) == NGX_OK && cookie_value.len == LOG_ID_LEN)
        {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                    "get cookie value");
            ngx_memcpy(v->data, cookie_value.data, LOG_ID_LEN);
            return NGX_OK;
        }
    }

    logid = ngx_http_logid_get_new_logid(r);
    if (logid->len == 0 || logid->data == NULL)
    {
        return NGX_ERROR;
    }

    ngx_memcpy(v->data, logid->data, LOG_ID_LEN);

    return NGX_OK;
}

static ngx_str_t*
ngx_http_logid_get_new_logid(ngx_http_request_t *r)
{
    ngx_str_t *logid;
    ngx_md5_t                    md5;
    u_char                       *end;
    u_char                       *val;
    u_char                       hashb[MD5_HASH_LEN];
    in_port_t port;
    char* addr;
    size_t i;

    logid = ngx_pnalloc(r->pool, sizeof(ngx_str_t));
    logid->len = LOG_ID_LEN;
    logid->data = ngx_pnalloc(r->pool, logid->len);
    if (logid->data == NULL) {
        return logid;
    }
    struct sockaddr_in *ip = (struct sockaddr_in *) (r->connection->sockaddr);
    addr = inet_ntoa(ip->sin_addr);
    port = ntohs(ip->sin_port);

    i = sizeof(ngx_pid) + sizeof(addr) - 1 + sizeof(port)
        + sizeof(r->start_sec) + sizeof(r->start_msec) 
        + sizeof(r->request_length) + r->headers_in.user_agent->value.len + 1;
    val = ngx_pnalloc(r->pool, i);
    end = ngx_sprintf(val, "%i,%s,%ui,%ui,%d,%O,%V",
                      ngx_pid, addr, port, r->start_sec, r->start_msec, r->request_length, &r->headers_in.user_agent->value);
    *end = 0;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "logid: data for hash=%s", val);

    ngx_md5_init(&md5);
    ngx_md5_update(&md5, val, end-val);
    ngx_md5_final(hashb, &md5);


    for(i = 0; i < MD5_HASH_LEN; i++)
    {
        sprintf((char *)(logid->data + i*2), "%02x", hashb[i]);
    }

    return logid;
}

static ngx_int_t
ngx_http_logid_cookie_parse(ngx_http_request_t *r, ngx_str_t *value)
{
    ngx_int_t                          rc;
    ngx_http_logid_conf_t  *conf;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_logid_module);

    /*
     * if cookie is too large,will there be any problems?
     */
    rc = ngx_http_parse_multi_header_lines(&r->headers_in.cookies,
                                           &conf->cookie_name, value);

    if (rc == NGX_DECLINED)
    {
        return rc;
    }

    return NGX_OK;
}
static ngx_int_t
ngx_logid_cookie_set(ngx_http_request_t *r, ngx_http_logid_conf_t *conf, ngx_str_t* value)
{
    u_char           *cookie, *p;
    size_t len;
    ngx_int_t         expires;
    ngx_table_elt_t  *set_cookie;
    if (value->data == NULL || value->len == 0)
    {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "cookie value is empty");
        return NGX_OK;
    }

    expires = ngx_time() + conf->cookie_expire_time;

    len = conf->cookie_name.len + 1 + value->len;
    if(conf->cookie_expire_time != 0) {
        len += sizeof("; expires=") - 1 + sizeof("Mon, 01 Sep 1970 00:00:00 GMT; ") - 1;
    }
    if(conf->cookie_domain.len != 0) {
        len += sizeof("domain=") - 1 + sizeof("; ") - 1 + conf->cookie_domain.len;
    }
    if(conf->cookie_path.len != 0) {
        len += sizeof("path=") - 1 + conf->cookie_path.len;
    }

    cookie = ngx_pnalloc(r->pool, len);
    if (cookie == NULL) {
        return NGX_ERROR;
    }

    p = ngx_copy(cookie, conf->cookie_name.data, conf->cookie_name.len);
    *p++ = '=';
    p = ngx_copy(p, value->data, value->len);

    if(conf->cookie_expire_time > 0) {
        p = ngx_cpymem(p, "; expires=", sizeof("; expires=") - 1);
        p = ngx_http_cookie_time(p, expires);
        p = ngx_cpymem(p, "; ", sizeof("; ") - 1);
    }

    if (conf->cookie_domain.len != 0) {
        p = ngx_cpymem(p, "domain=", sizeof("domain=") - 1);
        p = ngx_copy(p, conf->cookie_domain.data, conf->cookie_domain.len);
        p = ngx_cpymem(p, "; ", sizeof("; ") - 1);
    }

    if (conf->cookie_path.len != 0) {
        p = ngx_cpymem(p, "path=", sizeof("path=") - 1);
        p = ngx_copy(p, conf->cookie_path.data, conf->cookie_path.len);
    }

    set_cookie = ngx_list_push(&r->headers_out.headers);
    if (set_cookie == NULL) {
        return NGX_ERROR;
    }

    set_cookie->hash = 1;
    ngx_str_set(&set_cookie->key, "Set-Cookie");
    set_cookie->value.len = p - cookie;
    set_cookie->value.data = cookie;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "set cookie: \"%V\"", &set_cookie->value);

    return NGX_OK;
}


static void *
ngx_http_logid_create_conf(ngx_conf_t *cf)
{
    ngx_http_logid_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_logid_conf_t));
    if (conf == NULL)
    {
        return NGX_CONF_ERROR;
    }

    conf->enable = NGX_CONF_UNSET;
    conf->cookie_enable = NGX_CONF_UNSET;
    conf->cookie_expire_time = NGX_CONF_UNSET;
    return conf;
}


static char *
ngx_http_logid_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_logid_conf_t *prev = parent;
    ngx_http_logid_conf_t *conf = child;

    ngx_conf_merge_off_value(conf->enable, prev->enable, 0);
    ngx_conf_merge_off_value(conf->cookie_enable, prev->cookie_enable, 0);
    ngx_conf_merge_str_value(conf->cookie_name, prev->cookie_name, "");
    ngx_conf_merge_value(conf->cookie_expire_time, prev->cookie_expire_time, 0); 

    ngx_conf_merge_str_value(conf->cookie_domain, prev->cookie_domain, "");
    ngx_conf_merge_str_value(conf->cookie_path, prev->cookie_path, "");

    if (conf->cookie_enable)
    {
        if (conf->cookie_name.len == 0)
        {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "logid_cookie_name can not be empty");
            return NGX_CONF_ERROR;
        }
    }

    return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_logid_init(ngx_conf_t *cf)
{
    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_logid_header_filter;

    ngx_http_variable_t *var;

    var = ngx_http_add_variable(cf, &ngx_http_logid,
                                NGX_HTTP_VAR_CHANGEABLE);
    if (var == NULL)
    {
        return NGX_ERROR;
    }

    var->get_handler = ngx_http_logid_set_variable;

    return NGX_OK;
}
