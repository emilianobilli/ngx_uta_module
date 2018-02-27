/*
 * Copyright (C) Emiliano Billi 2018
 */


#include <ngx_config.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <string.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <time.h>

static time_t    gettime(ngx_str_t nstr);
static void *    ngx_http_uta_create_loc_conf(ngx_conf_t *cf);
static char *    ngx_http_uta(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_uta_handler(ngx_http_request_t *r);
static u_char *get_hmac_sha1(const u_char *key, int key_len, const u_char *d, int n, u_char *md, size_t md_len);
static u_char *sha1_hex(const u_char *md, u_char *hex);


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
    ngx_flag_t  time_expiration;		/* If use time of expiration */
} ngx_http_uta_loc_conf_t;

static void *ngx_http_uta_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_uta_loc_conf_t *conf;

    conf = ngx_pcalloc(cf->pool,sizeof(ngx_http_uta_loc_conf_t));
    if (conf == NULL) {
	return NGX_CONF_ERROR;
    }

    conf->time_expiration = NGX_CONF_UNSET;

    return conf;
}

static ngx_command_t ngx_http_uta_commands[] = {
    { ngx_string("uta"),
      NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
      ngx_http_uta,
      0,
      0,
      NULL },
    { ngx_string("secret"),
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
    { ngx_string("time_expiration"),
      NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_uta_loc_conf_t,time_expiration),
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
    ngx_http_uta_loc_conf_t  *lc; 
    ngx_http_core_loc_conf_t *clc;
    ngx_open_file_info_t      of;
    ngx_uint_t		      level;
    ngx_int_t 		      rc;
    ngx_str_t		      path,stime,etime,hash; /*,value;*/
    ngx_table_elt_t  	      *h;
    u_char 		      *last,*to_hash;
    size_t		      root;
    ngx_log_t                 *log;
    u_char		      md[20];	/* For hmac(sha1()) */
    u_char		      md_hex_str[40+1] = {0};
    size_t		      alloc_sz;

    log = r->connection->log;

    if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD))) {
	return NGX_HTTP_NOT_ALLOWED;
    }

    if (r->uri.data[r->uri.len-1] == '/') {
	return NGX_DECLINED;
    }

    if (r->args.len == 0) {
	return NGX_HTTP_NOT_FOUND;
    }

    ngx_log_error(NGX_LOG_DEBUG,log,0,"r->uri.data: %s,%d", r->uri.data, r->uri.len);
    ngx_log_error(NGX_LOG_DEBUG,log,0,"r->args.data: %s", r->args.data);

    rc = ngx_http_discard_request_body(r);
    if (rc != NGX_OK) {
	return rc;
    }

    last = ngx_http_map_uri_to_path(r,&path,&root,0);
    if (last == NULL) {
	return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    lc  = ngx_http_get_module_loc_conf(r,ngx_http_uta_module);


    if (ngx_http_arg(r,(u_char *) "hash",4,&hash) != NGX_OK) {
	return NGX_HTTP_FORBIDDEN;
    }

    /*
     * Check if hash is the last argument in r->args
     */
    if ( (r->args.data + r->args.len) - hash.len != hash.data) {
	return NGX_HTTP_FORBIDDEN;
    }

    if ( hash.len != 21 ) {		/* 0 + 20chars */
	return NGX_HTTP_FORBIDDEN;
    }
    

    /*
     * time_expiration on;
     * check if (stime < now < etime)
     */
    if (lc->time_expiration) {
	if (ngx_http_arg(r, (u_char *) "stime", 5, &stime) == NGX_OK) {
	    if (ngx_http_arg(r, (u_char *) "etime", 5, &etime) == NGX_OK) {
		if ( gettime(stime) == (time_t) -1 || time(NULL) < gettime(stime) || gettime(etime) == (time_t) -1 || time(NULL) > gettime(etime)) {
		    return NGX_HTTP_UNAUTHORIZED;
		}
	    }
	    else {
		return NGX_HTTP_FORBIDDEN;
	    }
	}
	else {
    	    return NGX_HTTP_FORBIDDEN;
	}	
    }

    /*
     *	r->uri.data:  /path/to/video/v.m3u8 
     *  r->uri.len:   21
     *  r->args.data: stime=YYYYMMDDHHMM&etime=YYYYMMDDHHMM&other_stuffs=OTHER&hash=012345678900987654321
     *  r->args.len:  82
     * 
     *  need space to: /path/to/video/v.m3u8?stime=YYYYMMDDHHMM&etime=YYYYMMDDHHMM&other_stuffs=OTHER
     *  r->uri.len:  21
     *  r->args.len: 82
     *  -4: "hash" word
     *  -2: '&' and '=' characters
     *  -hash.len: 21
     *  +2: '?' and '\0'
     */
    alloc_sz = r->uri.len + r->args.len - (4+2+hash.len) + 2;
    to_hash  = (u_char*) calloc(alloc_sz,1);

    if (to_hash == NULL) {
	return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    strncpy((char *)&to_hash[0]           ,(const char *)r->uri.data ,r->uri.len  + 1 );
    strncpy((char *)&to_hash[r->uri.len+1],(const char *)r->args.data,r->args.len - (4+2+hash.len));

    get_hmac_sha1(lc->secret.data,lc->secret.len,to_hash,strlen((char *)to_hash),md,20);
    /*
     * A esta altura tenemos el resumen
     */

    if (strncmp((const char*)sha1_hex((const u_char *)md,md_hex_str),(const char *)&(hash.data)[1],20)) {
	return NGX_HTTP_UNAUTHORIZED;
    }

    free(to_hash);

    path.len = last - path.data;

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
    r->headers_out.content_type.len  = sizeof("video/MP2T")-1;
    r->headers_out.content_type.data = (u_char *) "video/MP2T";

    h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    h->hash = 1;
    ngx_str_set(&h->key, "Access-Control-Allow-Origin");
    ngx_str_set(&h->value, "*");


    if (ngx_http_set_etag(r) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    /*
    if (ngx_http_set_content_type(r) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }*/

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

/* unsigned char *HMAC(const EVP_MD *evp_md, const void *key,
                       int key_len, const unsigned char *d, int n,
                       unsigned char *md, unsigned int *md_len);
*/
static u_char *get_hmac_sha1(const u_char *key, int key_len, const u_char *d, int n, u_char *md, size_t md_len)
{
    unsigned int mlen = (unsigned int)md_len;
    return HMAC(EVP_sha1(),key,key_len,d,n,md,(unsigned int *)&mlen);
}


static time_t gettime(ngx_str_t nstr)
{
    struct tm t;
    int i;
    char year[5] = {0};
    char mon[3]  = {0};
    char day[3]  = {0};
    char hh[3]   = {0};
    char mm[3]   = {0};

    memset (&t,0,sizeof(struct tm));

    if (nstr.len != 12)
        return (time_t) -1;

    for ( i = 0;(size_t) i <= nstr.len-1; i++ )
        if (!isdigit(nstr.data[i]))
            return (time_t) -1;

    strncpy(year,(char *)&(nstr.data)[0],4);
    strncpy(mon, (char *)&(nstr.data)[4],2);
    strncpy(day, (char *)&(nstr.data)[6],2);
    strncpy(hh,  (char *)&(nstr.data)[8],2);
    strncpy(mm,  (char *)&(nstr.data)[10],2);

    t.tm_min  = atoi(mm);
    t.tm_hour = atoi(hh);
    t.tm_mday = atoi(day);
    t.tm_mon  = atoi(mon) -1;
    t.tm_year = atoi(year)-1900;

    return mktime(&t);
}



static u_char *sha1_hex(const u_char *md, u_char *hex)
{
    int i;
    for(i = 0; i < 20; i++)
         sprintf((char *)&hex[i*2], "%02x", (unsigned int)md[i]);
    return hex;
}

