#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <sys/time.h>
#include <time.h>
#include <string.h>
#include <unistd.h>
#include <net/if.h>

#define PT_RAND_RANGE 1000
#define PT_LOGID_LENGTH 11
#define PT_TRACECODE_LENGTH 27
#define PT_UNIQID_LENGTH 27
#define PT_COMMENT_LENGTH ( sizeof("<!---->")-1 )
#define PT_LO_IP 16777343
#define PT_ORIGINAL "0"
#define PT_HTML "1"
#define PT_NOT_HTML "2"
#define MAX_JS_VALUE_LEN 8192

static ngx_int_t ngx_http_tracing_process_init(ngx_cycle_t *cycle);
static ngx_int_t ngx_http_get_variable_uniqid(ngx_http_request_t *r,ngx_http_variable_value_t *v, uintptr_t data);

static void* ngx_http_tracing_create_loc_conf(ngx_conf_t *cf);
static char* ngx_http_tracing_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);
static ngx_int_t ngx_http_get_logid_from_header(ngx_http_request_t *r);
static ngx_int_t ngx_http_get_variable_logid(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_get_variable_tracecode(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_get_variable_is_html(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_tracing_add_variables(ngx_conf_t *cf);
static ngx_int_t ngx_http_tracing_init(ngx_conf_t *cf);
static ngx_int_t ngx_http_tracecode_header_filter(ngx_http_request_t *r);
static ngx_int_t ngx_http_gen_tracecode(ngx_http_request_t *r, ngx_chain_t *in, ngx_chain_t *chain_link);
static ngx_int_t ngx_http_tracecode_body_filter(ngx_http_request_t *r, ngx_chain_t *in);
static ngx_int_t ngx_http_tracing_error_handler(ngx_http_request_t *r);
static u_char *ngx_http_tracing_log_error_handler(ngx_http_request_t *r, ngx_http_request_t *sr, u_char *buf, size_t len);

static ngx_int_t g_logid_index = -1;
static ngx_int_t g_tracecode_index = -1;
static ngx_int_t g_is_html_index = -1;
static ngx_uint_t g_local_ip = 0;

static ngx_int_t g_uniqid_index = -1;
static ngx_int_t g_x_bd_uniqid_index = -1;

typedef struct {
    ngx_flag_t enable;
    ngx_flag_t header_enable;    
    ngx_flag_t body_enable;    
    ngx_flag_t get_header_enable;
    ngx_flag_t white_page_rewrite_enable;
    ngx_str_t logid_name;
    ngx_str_t tracecode_name;
    ngx_str_t js_trace_page_logid_name;
    ngx_flag_t js_trace_logid_enable;
} ngx_http_tracing_loc_conf_t;

static ngx_command_t  ngx_http_tracing_commands[] = {
    {
        ngx_string("problem_tracing"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_flag_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_tracing_loc_conf_t, enable),
        NULL
    },
    {
        ngx_string("header_tracing"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_flag_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_tracing_loc_conf_t, header_enable),
        NULL
    },
    {
        ngx_string("body_tracing"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_flag_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_tracing_loc_conf_t, body_enable),
        NULL
    },
    {
        ngx_string("get_header"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_flag_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_tracing_loc_conf_t, get_header_enable),
        NULL
    },
    {
        ngx_string("white_page_rewrite"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_flag_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_tracing_loc_conf_t, white_page_rewrite_enable),
        NULL
    },
    {
        ngx_string("logid_name"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_tracing_loc_conf_t, logid_name),
        NULL
    },
    {
        ngx_string("tracecode_name"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_tracing_loc_conf_t, tracecode_name),
        NULL
    },

    {
        ngx_string("js_trace_page_logid_name"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_tracing_loc_conf_t, js_trace_page_logid_name),
        NULL
    },

    {
        ngx_string("js_trace_logid_enable"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_flag_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_tracing_loc_conf_t, js_trace_logid_enable),
        NULL
    },

    ngx_null_command
};

static ngx_http_variable_t ngx_http_logid_vars[] = {
    {
        ngx_string("logid"), 
        0,
        ngx_http_get_variable_logid, 0,
        NGX_HTTP_VAR_NOCACHEABLE|NGX_HTTP_VAR_NOHASH, 0
    },
    {
        ngx_string("tracecode"), 
        0,
        ngx_http_get_variable_tracecode, 0,
        NGX_HTTP_VAR_NOCACHEABLE|NGX_HTTP_VAR_NOHASH, 0
    },
    {
        ngx_string("is_html"), 
        0,
        ngx_http_get_variable_is_html, 0,
        NGX_HTTP_VAR_NOCACHEABLE|NGX_HTTP_VAR_NOHASH, 0
    },
    {
        ngx_string("uniqid"), 
        0,
        ngx_http_get_variable_uniqid, 0,
        NGX_HTTP_VAR_NOCACHEABLE|NGX_HTTP_VAR_NOHASH, 0
    },

    { ngx_null_string, NULL, NULL, 0, 0, 0 }
};

static ngx_http_module_t  ngx_http_tracing_module_ctx = {
    ngx_http_tracing_add_variables,     /* preconfiguration */
    ngx_http_tracing_init,              /* postconfiguration */

    NULL,                               /* create main configuration */
    NULL,                               /* init main configuration */

    NULL,                               /* create server configuration */
    NULL,                               /* merge server configuration */

    ngx_http_tracing_create_loc_conf,   /* create location configuration */
    ngx_http_tracing_merge_loc_conf     /* merge location configuration */
};


ngx_module_t  ngx_http_tracing_module = {
    NGX_MODULE_V1,
    &ngx_http_tracing_module_ctx,  /* module context */
    ngx_http_tracing_commands,     /* module directives */
    NGX_HTTP_MODULE,                             /* module type */
    NULL,                                        /* init master */
    NULL,                                        /* init module */
    ngx_http_tracing_process_init, /* init process */
    NULL,                                        /* init thread */
    NULL,                                        /* exit thread */
    NULL,                                        /* exit process */
    NULL,                                        /* exit master */
    NGX_MODULE_V1_PADDING
};

static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;
static ngx_http_output_body_filter_pt    ngx_http_next_body_filter;

static ngx_int_t ngx_http_tracing_process_init(ngx_cycle_t *cycle)
{
    struct hostent *h = NULL;
    ngx_uint_t i = 0;
    ngx_int_t pid = getpid();
    if(pid < 0) {
        srandom(time(NULL));
    } else {
        srandom(pid);
    }

    if(cycle->hostname.len != 0 && cycle->hostname.data != NULL) {
        cycle->hostname.data[cycle->hostname.len] = '\0';
        h = gethostbyname((char *)cycle->hostname.data);
        if (h == NULL || h->h_addr_list[0] == NULL) {
            g_local_ip = 0;
            ngx_log_error(NGX_LOG_ERR, cycle->log, 0, "host \"%s\" not found", cycle->hostname.data);
            return NGX_OK;
        }
        while(h->h_addr_list[i] != NULL && *(in_addr_t *)(h->h_addr_list[i]) == PT_LO_IP) {
            i++;
        }
        if(h->h_addr_list[i] == NULL) {
            ngx_log_error(NGX_LOG_ERR, cycle->log, 0, "get local ip failed");
            g_local_ip = 0;  
            return NGX_OK;
        } else {
            g_local_ip = *(in_addr_t *)(h->h_addr_list[i]);
        }
    } else {
        g_local_ip = 0;  
    }

    return NGX_OK;
}

static ngx_int_t
ngx_http_tracing_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t *var = NULL, *v = NULL;

    for(v = ngx_http_logid_vars; v->name.len; v++) {
        var = ngx_http_add_variable(cf, &v->name, v->flags);
        if(var == NULL) {
            ngx_log_error(NGX_LOG_ERR, cf->log, 0, "add variable %s failed!", v->name.data);
            return NGX_ERROR;
        }
        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return NGX_OK;
}

static ngx_int_t
ngx_http_get_logid_from_header(ngx_http_request_t *r)
{
    ngx_http_tracing_loc_conf_t *conf = NULL;
    conf = ngx_http_get_module_loc_conf(r, ngx_http_tracing_module);

    ngx_uint_t logid_key = 0;
    ngx_http_variable_value_t *logid_value = NULL;
    ngx_str_t http_str = ngx_string("http_");
    ngx_str_t *logid_str = &conf->logid_name;
    ngx_str_t http_logid_str;

    http_logid_str.len = http_str.len + logid_str->len;
    http_logid_str.data = (u_char *) ngx_pcalloc(r->connection->pool, http_logid_str.len + 1);
    if(http_logid_str.data == NULL){
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "http_logid_str alloc failed");
        goto ngx_error;
    }
    ngx_memcpy(http_logid_str.data, http_str.data, http_str.len);
    if(ngx_strlen((char *)http_logid_str.data) != http_str.len){
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "logid_str len error");
        goto ngx_error;
    }
    strncat((char*)http_logid_str.data, (char *)logid_str->data, logid_str->len);
    if(ngx_strlen((char *)http_logid_str.data) != http_logid_str.len){
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "http_logid_str strncat len error");
        goto ngx_error;
    }
    logid_key = ngx_hash_key(http_logid_str.data, http_logid_str.len);
    if(logid_key == 0){
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "logid_key error");
        goto ngx_error;
    }

    logid_value = ngx_http_get_variable(r, &http_logid_str, logid_key);
    if(logid_value == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "logid_value error");
        goto ngx_error;
    }
    if(logid_value ->not_found == 1 || logid_value->len == 0 || logid_value->data == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "logid_value not found");
    } else {
        r ->variables[g_logid_index].len= logid_value->len;
        r ->variables[g_logid_index].valid = 1;
        r ->variables[g_logid_index].not_found = 0;
        r ->variables[g_logid_index].no_cacheable = 0;
        r ->variables[g_logid_index].data = (u_char *)logid_value->data;

        return NGX_OK;
    }
ngx_error:
    return     NGX_ERROR;
}


static ngx_int_t
ngx_http_get_variable_logid(ngx_http_request_t *r,
        ngx_http_variable_value_t *v, uintptr_t data)
{
    struct timeval tv = {0, 0};
    char *logid = NULL;
    ngx_uint_t logid_real_len = 0;
    ngx_int_t random_number = 0;
    ngx_http_tracing_loc_conf_t *conf = NULL;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_tracing_module);
    if(!conf->enable) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "get logid failed,problem tracing is off");
        goto ngx_error;
    }
    
    if(conf->get_header_enable) {
        ngx_http_get_logid_from_header(r);
    }
    if(r->variables[g_logid_index].data != NULL) {
        if(r->variables[g_logid_index].len > PT_LOGID_LENGTH) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "logid len error");
            goto ngx_error;
        }
        return NGX_OK;
    } else {
        logid = (char *) ngx_pcalloc(r->connection->pool, PT_LOGID_LENGTH);
        if(logid == NULL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "logid alloc failed ");
            goto ngx_error;
        }
        ngx_gettimeofday(&tv);

        random_number = random() / (RAND_MAX + 1.0) * PT_RAND_RANGE;
        ngx_snprintf((u_char *)logid, PT_LOGID_LENGTH, "%04d%03d%03d", tv.tv_sec%3600, tv.tv_usec/1000, random_number);

        logid_real_len = strlen((char *)logid);
        if(logid_real_len >= PT_LOGID_LENGTH) {
            goto ngx_error;
        }

        r ->variables[g_logid_index].len= logid_real_len;
        r ->variables[g_logid_index].valid = 1;
        r ->variables[g_logid_index].not_found = 0;
        r ->variables[g_logid_index].no_cacheable = 0;
        r ->variables[g_logid_index].data = (u_char *)logid;

    }

    return NGX_OK;
ngx_error:
    return NGX_ERROR;
}


static ngx_int_t
ngx_http_get_variable_uniqid(ngx_http_request_t *r,
        ngx_http_variable_value_t *v, uintptr_t data)
{
    u_char *uniqid = NULL;
    ngx_int_t uniqid_length = 0;
    ngx_http_tracing_loc_conf_t *conf = NULL;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_tracing_module);

    if(!conf->enable) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "module is off");
        goto ngx_error;
    }
    if(r->variables[g_uniqid_index].data != NULL) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "already have uniqid");
        return NGX_OK;
    }

    uniqid = (u_char *) ngx_pcalloc(r->connection->pool, PT_UNIQID_LENGTH);
    if(uniqid == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "alloc error");
        goto ngx_error;
    }
     
    ngx_snprintf((u_char *)uniqid, PT_TRACECODE_LENGTH - 1, "%d", rand());

    uniqid_length = strlen((char *)uniqid);
    if(uniqid_length >= PT_TRACECODE_LENGTH) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "uniqid length is error");
        goto ngx_error;
    }

    v->len= uniqid_length;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = uniqid;

    r ->variables[g_uniqid_index].len = uniqid_length;
    r ->variables[g_uniqid_index].valid = 1;
    r ->variables[g_uniqid_index].not_found = 0;
    r ->variables[g_uniqid_index].no_cacheable = 0;
    r ->variables[g_uniqid_index].data = (u_char *)uniqid;

    return NGX_OK;
ngx_error:
    return NGX_ERROR;
}


static ngx_int_t
ngx_http_get_variable_tracecode(ngx_http_request_t *r,
        ngx_http_variable_value_t *v, uintptr_t data)
{
    u_char *logid = NULL;
    u_char *tracecode = NULL;
    ngx_uint_t tracecode_real_len = 0;
    ngx_int_t time_sec = 0;
    struct timeval tv = {0, 0};
    struct tm tblock = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    ngx_http_tracing_loc_conf_t *conf = NULL;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_tracing_module);

    if(!conf->enable) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "module is off");
        goto ngx_error;
    }
    if(r->variables[g_tracecode_index].data != NULL) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "already have tc");
        return NGX_OK;
    }

    if(ngx_http_get_variable_logid(r, v, (uintptr_t)"logid") != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "get logid error");
        goto ngx_error;
    }
    logid = (u_char *)(r->variables[g_logid_index].data); 

    tracecode = (u_char *) ngx_pcalloc(r->connection->pool, PT_TRACECODE_LENGTH);
    if(tracecode == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "alloc error");
        goto ngx_error;
    }

    ngx_gettimeofday(&tv);
    time_sec = tv.tv_sec;
    localtime_r((time_t *)&time_sec, &tblock);

    ngx_snprintf((u_char *)tracecode, PT_TRACECODE_LENGTH, "%s%010l%02d%02d%02d", 
            logid, 
            g_local_ip, 
            tblock.tm_mon + 1, 
            tblock.tm_mday, 
            tblock.tm_hour
        );

    tracecode_real_len = strlen((char *)tracecode);
    if(tracecode_real_len >= PT_TRACECODE_LENGTH) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "tracecode len error!");
        goto ngx_error;
    }

    v->len= tracecode_real_len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = tracecode;

    r ->variables[g_tracecode_index].len=tracecode_real_len;
    r ->variables[g_tracecode_index].valid = 1;
    r ->variables[g_tracecode_index].not_found = 0;
    r ->variables[g_tracecode_index].no_cacheable = 0;
    r ->variables[g_tracecode_index].data = (u_char *)tracecode;

    return NGX_OK;
ngx_error:
    return NGX_ERROR;
}

static ngx_int_t
ngx_http_get_variable_is_html(ngx_http_request_t *r,
        ngx_http_variable_value_t *v, uintptr_t data)
{
    r->variables[g_is_html_index].len = 1;
    r->variables[g_is_html_index].valid = 1;
    r->variables[g_is_html_index].not_found = 0;
    r->variables[g_is_html_index].no_cacheable = 0;
    r->variables[g_is_html_index].data = (u_char *)PT_ORIGINAL;

    return NGX_OK;
}

static ngx_int_t
ngx_http_tracing_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt *h = NULL;
    ngx_http_core_main_conf_t *cmcf = NULL;

    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_tracecode_header_filter;

    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_tracecode_body_filter;

    ngx_str_t logid = ngx_string("logid");
    g_logid_index = ngx_http_get_variable_index(cf, &logid);

    ngx_str_t tracecode = ngx_string("tracecode");
    g_tracecode_index = ngx_http_get_variable_index(cf, &tracecode);

    ngx_str_t is_html = ngx_string("is_html");
    g_is_html_index = ngx_http_get_variable_index(cf, &is_html);

    ngx_str_t uniqid = ngx_string("uniqid");
    g_uniqid_index = ngx_http_get_variable_index(cf, &uniqid);
	
    ngx_str_t x_bd_uniqid = ngx_string("http_x_bd_uniqid");
    g_x_bd_uniqid_index = ngx_http_get_variable_index(cf, &x_bd_uniqid);

    if(g_logid_index == NGX_ERROR || g_tracecode_index == NGX_ERROR || 
           g_is_html_index == NGX_ERROR || g_uniqid_index == NGX_ERROR || 
           g_x_bd_uniqid_index == NGX_ERROR) {
        ngx_log_error(NGX_LOG_ERR, cf->log, 0, "get g_logid_index or g_tracecode_index or g_is_html_index failed!");
        return NGX_ERROR;
    }

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    h = ngx_array_push(&cmcf->phases[NGX_HTTP_POST_READ_PHASE].handlers);
    if(h == NULL){
        return NGX_ERROR;
    }
    *h = ngx_http_tracing_error_handler;
    srand((time(NULL) + g_local_ip));

    return NGX_OK;
}

static ngx_int_t
ngx_http_tracecode_header_filter(ngx_http_request_t *r)
{
    ngx_table_elt_t *set_tracecode = NULL;
    ngx_http_tracing_loc_conf_t *conf = NULL;
    conf = ngx_http_get_module_loc_conf(r, ngx_http_tracing_module);

    if(!conf->enable || !conf->header_enable) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "header filter failed, problem tracing is off");
        return ngx_http_next_header_filter(r);
    }
    
    if(g_tracecode_index < 0 || g_logid_index < 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "get g_tracecode_index or g_logid_index failed!");
        goto ngx_error;
    }
    if(ngx_http_get_variable_tracecode(r, &r->variables[g_tracecode_index], ( uintptr_t )"tracecode") != NGX_OK){
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "get tracecode error");
        goto ngx_error;
    }
    set_tracecode = ngx_list_push(&r->headers_out.headers);
    if(set_tracecode == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "push tracecode to headers_out failed!\n");
        goto ngx_error;
    }
    set_tracecode ->hash = 1;
    set_tracecode->key = conf->tracecode_name;
    set_tracecode->value.len = r->variables[g_tracecode_index].len;
    set_tracecode->value.data = r->variables[g_tracecode_index].data;
    
    ngx_http_clear_content_length(r);
    return ngx_http_next_header_filter(r);
ngx_error:
    return NGX_ERROR;
}

static ngx_int_t
ngx_http_gen_tracecode(ngx_http_request_t *r, ngx_chain_t *in, ngx_chain_t *chain_link)
{
    u_char *out = NULL;
    u_char *out_end = NULL;
    ngx_buf_t *b = NULL;
    ngx_chain_t *added_link = NULL;
  
    ngx_http_tracing_loc_conf_t *conf = NULL;
    conf = ngx_http_get_module_loc_conf(r, ngx_http_tracing_module);

        ngx_int_t total_use_length = PT_TRACECODE_LENGTH + PT_COMMENT_LENGTH + 
                                     PT_LOGID_LENGTH + conf->js_trace_page_logid_name.len + MAX_JS_VALUE_LEN;

    out = (u_char *)ngx_pcalloc(r->pool, total_use_length);
    if(out == NULL){
        goto ngx_error;
    }
        if(conf -> js_trace_logid_enable){
        out_end = ngx_snprintf((u_char *)out, total_use_length,
                     "<!--%s-->\n<script> var %s = %s; </script>", 
                     r->variables[g_tracecode_index].data,
                     conf -> js_trace_page_logid_name.data,
                     r->variables[g_logid_index].data
                     );
        }else{
        out_end = ngx_snprintf((u_char *)out, total_use_length, 
                     "<!--%s-->", 
                     r->variables[g_tracecode_index].data
                     );

        }
    if(out_end == NULL){
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_snprintf return NULL while gen_tracecode");
        goto ngx_next_body;
    }

    b = ngx_calloc_buf(r->pool);
    if(b == NULL) {
        goto ngx_error;
    }
    b->pos = out;
    b->last = b->pos + (out_end - out);
    b->memory = 1;

    added_link = ngx_pcalloc(r->pool, sizeof(ngx_chain_t));
    if(added_link == NULL){
        goto ngx_error;
    }
    if(ngx_buf_size(chain_link->buf))
    {
        added_link->buf = b;
        added_link->next = NULL;
        chain_link->next = added_link;
        chain_link->buf->last_buf = 0;
        added_link->buf->last_buf = 1;

        goto ngx_next_body;
    }

    added_link->buf = b;
    added_link->next = chain_link;
    added_link->buf->last_buf = 0;
    chain_link->buf->last_buf = 1;
    if(chain_link != in) {
        ngx_chain_t *before_chain_link = in;
        while(before_chain_link != NULL && before_chain_link ->next != chain_link )
            before_chain_link = before_chain_link->next;
        if(before_chain_link == NULL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "before_chain_link failed");
            goto ngx_error;
        } else {
            before_chain_link ->next = added_link;
            goto ngx_next_body;
        }
    } else {
        return ngx_http_next_body_filter(r, added_link);
    }

ngx_error:
    return NGX_ERROR;
ngx_next_body:
    return ngx_http_next_body_filter(r, in);
}
static ngx_int_t
ngx_http_tracecode_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    u_char *pointer = NULL;
    ngx_chain_t *chain_link = in;
    ngx_int_t chain_contains_last_buffer = 0;

    ngx_http_tracing_loc_conf_t *conf = NULL;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_tracing_module);
    if(!conf->enable || !conf->body_enable) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "module is off");
        goto ngx_next_body;
    }

    if(g_is_html_index < 0) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "g_is_html_index < 0");
        return NGX_ERROR;
    }
    if (in == NULL || r->header_only || in->buf == NULL) {
        goto ngx_next_body;
    }

    if(r->variables[g_is_html_index].data == NULL){
        ngx_http_get_variable_is_html(r, &r->variables[g_is_html_index], ( uintptr_t )"is_html");    
    }
    if(!strncmp((char *)(r->variables[g_is_html_index].data), PT_ORIGINAL, 1)) {
        pointer = in->buf->pos;
        while(pointer < in->buf->last && (*pointer == '\n' || *pointer == '\r' || *pointer == ' ')){
            pointer++;
        }
        if(pointer != NULL && !strncmp((const char *)pointer, "<!DOCTYPE", 9)){
            r->variables[g_is_html_index].data = (u_char *)PT_HTML;
            r->variables[g_is_html_index].len = 1;
        } else {
            r->variables[g_is_html_index].data = (u_char *)PT_NOT_HTML;
            r->variables[g_is_html_index].len = 1;
        }
    }
    for ( chain_link = in; chain_link != NULL; chain_link = chain_link->next ) {
        if (chain_link->buf->last_buf) {
            chain_contains_last_buffer = 1;
        }
        if(chain_link ->next == NULL) {
            break;
        }
    }
    if (chain_contains_last_buffer && !strncmp((const char *)(r->variables[g_is_html_index].data), PT_HTML, 1)) {
        return ngx_http_gen_tracecode(r, in, chain_link);
    } else {
        goto ngx_next_body;
    }

ngx_next_body:
    return ngx_http_next_body_filter(r, in);
}

static ngx_int_t
ngx_http_tracing_error_handler(ngx_http_request_t *r)
{
    r->log_handler = ngx_http_tracing_log_error_handler;

    return NGX_DECLINED;
}

static u_char *
ngx_http_tracing_log_error_handler(ngx_http_request_t *r, ngx_http_request_t *sr,
    u_char *buf, size_t len)
{
    char *uri_separator;
    u_char *p;
    ngx_http_upstream_t *u;
    ngx_http_core_srv_conf_t *cscf;

    if(r->variables[g_logid_index].data != NULL ) {
        p = ngx_snprintf(buf, len, ", logid: %v, ", &(r->variables[g_logid_index]));
        len -= p - buf;
        buf = p;
    }else{    
        p = ngx_snprintf(buf, len, ", -, ", &(r->variables[g_logid_index]));
        len -= p - buf;
        buf = p;
    }

    if(r->variables[g_tracecode_index].data != NULL ) {
        p = ngx_snprintf(buf, len, " tracecode: %v, ", &(r->variables[g_tracecode_index]));
        len -= p - buf;
        buf = p;
    }else{
        p = ngx_snprintf(buf, len, " -, ", &(r->variables[g_logid_index]));
        len -= p - buf;
        buf = p;
    }

    cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);

    p = ngx_snprintf(buf, len, " server: %V, ", &cscf->server_name);
    len -= p - buf;
    buf = p;

    if (r->request_line.data == NULL && r->request_start) {
        for (p = r->request_start; p < r->header_in->last; p++) {
            if (*p == CR || *p == LF) {
                break;
            }
        }

        r->request_line.len = p - r->request_start;
        r->request_line.data = r->request_start;
    }

    if (r->request_line.len) {
        p = ngx_snprintf(buf, len, " request: \"%V\", ", &r->request_line);
        len -= p - buf;
        buf = p;
    }else{

        p = ngx_snprintf(buf, len, " -, ", &(r->variables[g_logid_index]));
        len -= p - buf;
        buf = p;
    }

    if (r != sr) {
        p = ngx_snprintf(buf, len, " subrequest: \"%V\", ", &sr->uri);
        len -= p - buf;
        buf = p;
    }else{
        p = ngx_snprintf(buf, len, " -, ", &(r->variables[g_logid_index]));
        len -= p - buf;
        buf = p;

    }

    u = sr->upstream;

    if (u && u->peer.name) {

        uri_separator = "";

#if (NGX_HAVE_UNIX_DOMAIN)
        if (u->peer.sockaddr && u->peer.sockaddr->sa_family == AF_UNIX) {
            uri_separator = ":";
        }
#endif

        p = ngx_snprintf(buf, len, " upstream: \"%V%V%s%V\", ",
                &u->schema, u->peer.name,
                uri_separator, &u->uri);
        len -= p - buf;
        buf = p;
    }
    else{
        p = ngx_snprintf(buf, len, " -, ", &(r->variables[g_logid_index]));
        len -= p - buf;
        buf = p;
    }

    if (r->headers_in.host) {
        p = ngx_snprintf(buf, len, " host: \"%V\", ",
                &r->headers_in.host->value);
        len -= p - buf;
        buf = p;
    }

    if (r->headers_in.referer) {
        p = ngx_snprintf(buf, len, " referrer: \"%V\", ",
                &r->headers_in.referer->value);
        len -= p -buf;
        buf = p;
    }

    if(r->variables[g_x_bd_uniqid_index].data != NULL ) {
        p = ngx_snprintf(buf, len, " x_bd_uniqid: %v, ", &(r->variables[g_x_bd_uniqid_index]));
        len -= p - buf;
        buf = p;
    }
    else {
        p = ngx_snprintf(buf, len, " -, ", &(r->variables[g_logid_index]));
        len -= p - buf;
        buf = p;
    }

    if(r->variables[g_uniqid_index].data != NULL ) {
        p = ngx_snprintf(buf, len, " uniqid: %v, ", &(r->variables[g_uniqid_index]));
        len -= p - buf;
        buf = p;
    }
    else {
        p = ngx_snprintf(buf, len, " -, ", &(r->variables[g_logid_index]));
        len -= p - buf;
        buf = p;
    }


    return buf;
}

static void *
ngx_http_tracing_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_tracing_loc_conf_t  *conf = NULL;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_tracing_loc_conf_t));
    if (conf == NULL) {
        ngx_log_error(NGX_LOG_ERR, cf->log, 0, "conf alloc failed");
        return NGX_CONF_ERROR;
    }

    conf->enable = NGX_CONF_UNSET;
    conf->header_enable = NGX_CONF_UNSET;
    conf->body_enable = NGX_CONF_UNSET;
    conf->get_header_enable = NGX_CONF_UNSET;
    conf->white_page_rewrite_enable = NGX_CONF_UNSET;
    conf->logid_name.data = NULL;
    conf->tracecode_name.data = NULL;
    conf->js_trace_page_logid_name.data = NULL;
    conf->js_trace_logid_enable = NGX_CONF_UNSET;

    return conf;
}
static char *
ngx_http_tracing_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_tracing_loc_conf_t *prev = parent;
    ngx_http_tracing_loc_conf_t *conf = child;

    ngx_conf_merge_value(conf->enable, prev->enable, 1);
    ngx_conf_merge_value(conf->header_enable, prev->header_enable, 1);
    ngx_conf_merge_value(conf->body_enable, prev->body_enable, 1);
    ngx_conf_merge_value(conf->get_header_enable, prev->get_header_enable, 1);
    ngx_conf_merge_value(conf->white_page_rewrite_enable, prev->white_page_rewrite_enable, 1);
    ngx_conf_merge_str_value(conf->logid_name, prev->logid_name, "logid");
    ngx_conf_merge_str_value(conf->tracecode_name, prev->tracecode_name, "tracecode");
    ngx_conf_merge_str_value(conf->js_trace_page_logid_name, prev->js_trace_page_logid_name, "_trace_page_logid");
    ngx_conf_merge_value(conf->js_trace_logid_enable, prev->js_trace_logid_enable, 1);

    return NGX_CONF_OK;
}


