/*
 * Copyright (C) Emiliano Billi 2018
 */


#include <ngx_config.h>
#include <string.h>
#include <ngx_core.h>
#include <ngx_http.h>

static void *ngx_http_uta_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_uta(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_uta_handler(ngx_http_request_t *r);


ngx_http_module_t ngx_http_uta_module_ctx = {
    NULL,       			    /* Preconfig */
    NULL,       			    /* Post Config */
    NULL,       			    /* Main config */
    NULL,       /* Init main config */
    NULL,       /* Service Config */
    NULL,       /* Merge service config */
    ngx_http_uta_create_loc_conf,       /* Local Config */
    NULL        /* Merge local config */
};


typedef struct {
    ngx_str_t 	secret;
    ngx_str_t   hmac;		/* sha1 or sha256 */
    ngx_flag_t  time;		/* If use time of expiration */
} ngx_http_uta_loc_conf_t;

static void *ngx_http_uta_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_uta_loc_conf_t *conf;

    conf = ngx_pcalloc(cf->pool,sizeof(ngx_http_uta_loc_conf_t));
    if (conf == NULL) {
	return NGX_CONF_ERROR;
    }
    return conf;
}

static ngx_command_t ngx_http_uta_commands[] = {
    { ngx_string("uta"),
      NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
      ngx_http_uta,
      0,
      0,
      NULL },
    { ngx_string("scret"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_uta_loc_conf_t,secret),
      NULL },
    { ngx_string("hmac"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_uta_loc_conf_t,hmac),
      NULL },
    { ngx_string("time"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_uta_loc_conf_t, time),
      NULL },
    ngx_null_command
};

ngx_module_t ngx_http_uta_module = {
    NGX_MODULE_V1,
    &ngx_http_uta_module_ctx,       /* Module context */
    ngx_http_uta_commands,          /* Directivas */
    NGX_HTTP_MODULE,                /* Tipo de modulo */
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NGX_MODULE_V1_PADDING
};
static ngx_int_t ngx_http_uta_handler(ngx_http_request_t *r)
{
    ngx_buf_t *b;
    ngx_chain_t out;
/*    ngx_http_uta_loc_conf_t  *lc;  */
    ngx_http_core_loc_conf_t *clc;
    ngx_open_file_info_t      of;
    ngx_uint_t		      level;
    ngx_int_t 		      rc;
    ngx_str_t		      path; /*,value;*/
    u_char 		      *last;
    size_t		      root;
    ngx_log_t                 *log;


    log = r->connection->log;

    if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD))) {
	return NGX_HTTP_NOT_ALLOWED;
    }

    if (r->uri.data[r->uri.len-1] == '/') {
	return NGX_DECLINED;
    }

    ngx_log_error(NGX_LOG_DEBUG,log,0,"r->uri.data: %s", r->uri.data);
    ngx_log_error(NGX_LOG_DEBUG,log,0,"r->args.data: %s", r->args.data);

    rc = ngx_http_discard_request_body(r);
    if (rc != NGX_OK) {
	return rc;
    }

    last = ngx_http_map_uri_to_path(r,&path,&root,0);
    if (last == NULL) {
	return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    

    path.len = last - path.data;
    
/*    lc  = ngx_http_get_module_loc_conf(r,ngx_http_uta_module); */

    if (r->args.len == 0) {
	return NGX_HTTP_NOT_FOUND;
    }

    clc = ngx_http_get_module_loc_conf(r,ngx_http_core_module);
    
    ngx_memzero(&of, sizeof(ngx_open_file_info_t));

    of.read_ahead = clc->read_ahead;
    of.directio   = NGX_MAX_OFF_T_VALUE;
    of.valid      = clc->open_file_cache_valid;
    of.min_uses   = clc->open_file_cache_min_uses;
    of.errors     = clc->open_file_cache_errors;
    of.events     = clc->open_file_cache_events;

    if (ngx_open_cached_file(clc->open_file_cache, &path, &of, r->pool)
        != NGX_OK)
    {
        switch (of.err) {

        case 0:
            return NGX_HTTP_INTERNAL_SERVER_ERROR;

        case NGX_ENOENT:
        case NGX_ENOTDIR:
        case NGX_ENAMETOOLONG:

            level = NGX_LOG_ERR;
            rc = NGX_HTTP_NOT_FOUND;
            break;

        case NGX_EACCES:
#if (NGX_HAVE_OPENAT)
        case NGX_EMLINK:
        case NGX_ELOOP:
#endif

            level = NGX_LOG_ERR;
            rc = NGX_HTTP_FORBIDDEN;
            break;

        default:

            level = NGX_LOG_CRIT;
            rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
            break;
        }

        if (rc != NGX_HTTP_NOT_FOUND || clc->log_not_found) {
            ngx_log_error(level, log, of.err,
                          "%s \"%s\" failed", of.failed, path.data);
        }

        return rc;
    }
    if (!of.is_file) {
        ngx_log_error(NGX_LOG_CRIT, log, 0,
                      "\"%s\" is not a regular file", path.data);

        return NGX_HTTP_NOT_FOUND;
    }

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = of.size;
    r->headers_out.last_modified_time = of.mtime;

    if (ngx_http_set_etag(r) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (ngx_http_set_content_type(r) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (r != r->main && of.size == 0) {
        return ngx_http_send_header(r);
    }

    r->allow_ranges = 1;

    b = ngx_palloc(r->pool,sizeof(ngx_buf_t));
    if (b == NULL) {
	return NGX_HTTP_INTERNAL_SERVER_ERROR;
    } 
    b->file = ngx_pcalloc(r->pool,sizeof(ngx_file_t));
    if (b->file == NULL) {
	return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }


    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
	return rc;
    }

    b->file_pos  = 0;
    b->file_last = of.size;

    b->in_file  = b->file_last ? 1: 0;
    b->last_buf = (r == r->main) ? 1: 0;
    b->last_in_chain = 1;

    b->file->fd = of.fd;
    b->file->name = path;
    b->file->directio = of.is_directio;

    out.buf  = b;
    out.next = NULL;


    return ngx_http_output_filter(r,&out);
}

static char *ngx_http_uta(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t *clcf;
    clcf = ngx_http_conf_get_module_loc_conf(cf,ngx_http_core_module);
    clcf->handler = ngx_http_uta_handler;
    return NGX_CONF_OK;
}

