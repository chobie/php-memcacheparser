/*
 * memache_parser
 *
 * Copyright (C) 2008 FURUHASHI Sadayuki
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

#include "memcache_parser.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#define MARK(M, FPC) (parser->M = FPC - data)
#define MARK_LEN(M, FPC) (FPC - (parser->M + data))
#define MARK_PTR(M) (parser->M + data)

#define NUM_BUF_MAX 20

#define SET_INTEGER(DST, M, FPC, STRFUNC) \
	do { \
		pos = MARK_PTR(M); \
		if(pos[0] == '0') { parser->DST = 0; } \
		else { \
			len = MARK_LEN(M, FPC); \
			if(len > NUM_BUF_MAX) { goto convert_error; } \
			memcpy(buf, pos, len); \
			buf[len] = '\0'; \
			parser->DST = STRFUNC(buf, NULL, 10); \
			if(parser->DST == 0) { goto convert_error; } \
		} \
	} while(0)

#define SET_UINT(DST, M, FPC) \
	SET_INTEGER(DST, M, FPC, strtoul)

#define SET_ULL(DST, M, FPC) \
	SET_INTEGER(DST, M, FPC, strtoull)

#define SET_MARK_LEN(DST, M, FPC) \
		parser->DST = MARK_LEN(M, FPC);

/* this macro is magical. be careful. */
#define CALLBACK(INDEX, TYPE) \
	(((TYPE*)(&parser->callback))[parser->INDEX] == NULL) ? \
	-1 : \
	((TYPE*)(&parser->callback))[parser->INDEX]


enum {
	CMD_GET,

	CMD_SET,
	CMD_REPLACE,
	CMD_APPEND,
	CMD_PREPEND,

	CMD_CAS,

	CMD_DELETE,

	CMD_QUIT,
};

%%{
	machine memcache_parser;

	action reset {
		parser->keys = 0;
		parser->noreply = false;
		parser->time = 0;
	}

	action mark_key {
		MARK(key_pos[parser->keys], fpc);
	}
	action key {
		SET_MARK_LEN(key_len[parser->keys], key_pos[parser->keys], fpc);
	}
	action incr_key {
		++parser->keys;
	}

	action mark_flags {
		MARK(flags, fpc);
	}
	action flags {
		SET_UINT(flags, flags, fpc);
	}

	action mark_exptime {
		MARK(exptime, fpc);
	}
	action exptime {
		SET_ULL(exptime, exptime, fpc);
	}

	action mark_bytes {
		MARK(bytes, fpc);
	}
	action bytes {
		SET_UINT(bytes, bytes, fpc);
	}

	action noreply {
		parser->noreply = true;
	}

	action mark_time {
		MARK(time, fpc);
	}
	action time {
		SET_ULL(time, time, fpc);
	}

	action mark_cas_unique {
		MARK(cas_unique, fpc);
	}
	action cas_unique {
		SET_ULL(cas_unique, cas_unique, fpc);
	}

	action data_start {
		MARK(data_pos, fpc+1);
		parser->data_count = parser->bytes;
		fcall data;
	}
	action data {
		if(--parser->data_count == 0) {
			//printf("mark %d\n", parser->data_pos);
			//printf("fpc %p\n", fpc);
			//printf("data %p\n", data);
			SET_MARK_LEN(data_len, data_pos, fpc+1);
			fret;
		}
	}


	action cmd_get     { parser->command = CMD_GET;     }

	action cmd_set     { parser->command = CMD_SET;     }
	action cmd_replace { parser->command = CMD_REPLACE; }
	action cmd_append  { parser->command = CMD_APPEND;  }
	action cmd_prepend { parser->command = CMD_PREPEND; }

	action cmd_cas     { parser->command = CMD_CAS;     }

	action cmd_delete  { parser->command = CMD_DELETE;  }

	action cmd_quit    { parser->command = CMD_QUIT;    }


	action do_retrieval {
		unsigned int i;
		++parser->keys;
		for(i=0; i < parser->keys; ++i) {
			parser->key_pos[i] = (size_t)MARK_PTR(key_pos[i]);
		}
		if( CALLBACK(command, memcache_parser_callback_retrieval)(
				(const char**)parser->key_pos, parser->key_len, parser->keys,
				parser->user
				) < -1 ) { goto convert_error; }
	}

	action do_storage {
		if( CALLBACK(command, memcache_parser_callback_storage)(
				MARK_PTR(key_pos[0]), parser->key_len[0],
				parser->flags,
				parser->exptime,
				MARK_PTR(data_pos), parser->data_len,
				parser->noreply,
				parser->user
				) < -1 ) { goto convert_error; }
	}

	action do_cas {
		if( CALLBACK(command, memcache_parser_callback_cas)(
				MARK_PTR(key_pos[0]), parser->key_len[0],
				parser->flags,
				parser->exptime,
				MARK_PTR(data_pos), parser->data_len,
				parser->cas_unique,
				parser->noreply,
				parser->user
				) < -1 ) { goto convert_error; }
	}

	action do_delete {
		if( CALLBACK(command, memcache_parser_callback_delete)(
				MARK_PTR(key_pos[0]), parser->key_len[0],
				parser->time, parser->noreply,
				parser->user
				) < -1 ) { goto convert_error; }
	}

	action do_quit {
		if ( CALLBACK(command, memcache_parser_callback_quit)(parser->user) < -1) {
			goto convert_error;
		}
	}

	key        = ([\!-\~]+)          >mark_key        %key;
	flags      = ('0' | [1-9][0-9]*) >mark_flags      %flags;
	exptime    = ('0' | [1-9][0-9]*) >mark_exptime    %exptime;
	bytes      = ([1-9][0-9]*)       >mark_bytes      %bytes;
	noreply    = ('noreply')         %noreply;
	time       = ('0' | [1-9][0-9]*) >mark_time       %time;
	cas_unique = ('0' | [1-9][0-9]*) >mark_cas_unique %cas_unique;


	retrieval_command = ('get' 's'?) @cmd_get;

	storage_command = ('set'     ) @cmd_set
					| ('replace' ) @cmd_replace
					| ('append'  ) @cmd_append
					| ('prepend' ) @cmd_prepend
					;

	cas_command = ('cas') @cmd_cas;

	delete_command = ('delete') @cmd_delete;

	quit_command = ('quit') @cmd_quit;

	retrieval = retrieval_command ' ' key (' ' key >incr_key)*
				(' ')?
				'\r\n';

	storage = storage_command ' ' key
				' ' flags ' ' exptime ' ' bytes
				(' ' noreply)?
				'\r\n'
				@data_start
				'\r\n'
				;

	cas = cas_command ' ' key
				' ' flags ' ' exptime ' ' bytes
				' ' cas_unique
				(' ' noreply)?
				'\r\n'
				@data_start
				'\r\n'
				;

	delete = delete_command ' ' key
				(' ' time)? (' ' noreply)?
				'\r\n'
				;

	quit = quit_command
				'\r\n'
				;

	command = retrieval @do_retrieval
			| storage   @do_storage
			| cas       @do_cas
			| delete    @do_delete
			| quit      @do_quit
			;

main := (command >reset)+;

data := (any @data)*;
}%%


%% write data;

void memcache_parser_init(memcache_parser* parser, memcache_parser_callback* callback, void* user)
{
	int cs = 0;
	int top = 0;
	%% write init;
	memset(parser, 0, sizeof(memcache_parser));
	parser->cs = cs;
	parser->callback = *callback;
	parser->user = user;
}

int memcache_parser_execute(memcache_parser* parser, const char* data, size_t len, size_t* off)
{
	const char* p = data + *off;
	const char* pe = data + len;
	const char* eof = pe;
	int cs = parser->cs;
	int top = parser->top;
	int* stack = parser->stack;
	const char* pos;
	char buf[NUM_BUF_MAX+1];

	//printf("execute, len:%lu, off:%lu\n", len, *off);
	//printf("%s\n", data);
	//printf("data: ");
	//int i;
	//for(i=0; i < len; ++i) {
	//	printf("0x%x ", (int)data[i]);
	//}
	//printf("\n");

	%% write exec;

ret:

	parser->cs = cs;
	parser->top = top;
	*off = p - data;

	if(cs == memcache_parser_error) {
		return -1;
	} else if(cs == memcache_parser_first_final) {
		return 1;
	} else {
		return 0;
	}

convert_error:
	cs = memcache_parser_error;
	goto ret;
}


/* PHP Extension */

static int memcache_parser_resource_handle;


void static destruct_memcache_parser(zend_rsrc_list_entry *rsrc TSRMLS_DC)
{
	php_memcache_parser_t *obj = (php_memcache_parser_t *)rsrc->ptr;
	if (obj->callback != NULL) {
		if (obj->callback->fci.function_name != NULL) {
			zval_ptr_dtor(&obj->callback->fci.function_name);
		}
		if (obj->callback->fci.object_ptr != NULL) {
			zval_ptr_dtor(&obj->callback->fci.object_ptr);
		}
		efree(obj->callback);
	}
	efree(obj);
}

static int php_memcache_parser_do_callback(zval **retval_ptr, php_memcache_parser_t *ctx, zval ***params, int param_count TSRMLS_DC)
{
	int error = 0;
	
	if (ZEND_FCI_INITIALIZED(ctx->callback->fci)) {
		ctx->callback->fci.params         = params;
		ctx->callback->fci.retval_ptr_ptr = retval_ptr;
		ctx->callback->fci.param_count    = param_count;
		ctx->callback->fci.no_separation  = 1;

		if (zend_call_function(&ctx->callback->fci, &ctx->callback->fcc TSRMLS_CC) != SUCCESS) {
			error = -1;
		}
	} else {
		error = -2;
	}
	
	return error;
}

static int php_memcache_parser_retrieval(
		const char** key, unsigned* key_len, unsigned keys,
		void* user)
{
	TSRMLS_FETCH();
	zval **params[3], *z_command, *z_key, *z_opts, *retval = NULL;
	php_memcache_parser_t *ctx = (php_memcache_parser_t*)user;
	int i = 0;

	MAKE_STD_ZVAL(z_command);
	MAKE_STD_ZVAL(z_key);
	MAKE_STD_ZVAL(z_opts);
	
	ZVAL_STRING(z_command, "get", 1);
	ZVAL_STRINGL(z_key, *key, *key_len, 1);
	array_init(z_opts);

	for(i = 0; i < keys; ++i) {
		//rb_ary_push(rbkeys, rb_str_new(key[i], key_len[i]));
	}
	add_assoc_long_ex(z_opts, "keys", sizeof("keys"), keys);
	
	params[0] = &z_command;
	params[1] = &z_key;
	params[2] = &z_opts;

	php_memcache_parser_do_callback(&retval, ctx, params, 3 TSRMLS_CC);

	if (retval != NULL) {
		zval_ptr_dtor(&retval);
	}
	
	zval_ptr_dtor(params[0]);
	zval_ptr_dtor(params[1]);
	zval_ptr_dtor(params[2]);
	
	return 0;
}

#define php_memcache_parser_storage(NAME) \
	static int php_memcache_parser_storage_##NAME( \
			const char* key, unsigned key_len, \
			unsigned short flags, uint64_t exptime, \
			const char* data, unsigned data_len, \
			bool noreply, \
			void* user) \
	{ \
		TSRMLS_FETCH();\
		zval **params[3], *z_command, *z_key, *z_opts, *retval = NULL;\
		php_memcache_parser_t *ctx = (php_memcache_parser_t*)user;\
		int i = 0;\
\
		MAKE_STD_ZVAL(z_command);\
		MAKE_STD_ZVAL(z_key);\
		MAKE_STD_ZVAL(z_opts);\
		\
		ZVAL_STRING(z_command, #NAME, 1);\
		ZVAL_STRINGL(z_key, key, key_len, 1);\
		array_init(z_opts);\
\
		add_assoc_long_ex(z_opts, "flags", sizeof("flags"), flags);\
		add_assoc_long_ex(z_opts, "exptime", sizeof("exptime"), exptime);\
		add_assoc_stringl_ex(z_opts, "data", sizeof("data"), data, data_len, 1);\
		add_assoc_long_ex(z_opts, "noreply", sizeof("noreply"), noreply);\
		\
		params[0] = &z_command;\
		params[1] = &z_key;\
		params[2] = &z_opts;\
\
		php_memcache_parser_do_callback(&retval, ctx, params, 3 TSRMLS_CC);\
\
		if (retval != NULL) {\
			zval_ptr_dtor(&retval);\
		}\
		\
		zval_ptr_dtor(params[0]);\
		zval_ptr_dtor(params[1]);\
		zval_ptr_dtor(params[2]);\
		\
		return 0;\
	}

php_memcache_parser_storage(set);
php_memcache_parser_storage(replace);
php_memcache_parser_storage(append);
php_memcache_parser_storage(prepend);


static int php_memcache_parser_cas(
		const char* key, unsigned key_len,
		unsigned short flags, uint64_t exptime,
		const char* data, unsigned data_len,
		uint64_t cas_unique,
		bool noreply,
		void* user)
{
	TSRMLS_FETCH();
	zval **params[3], *z_command, *z_key, *z_opts, *retval = NULL;
	php_memcache_parser_t *ctx = (php_memcache_parser_t*)user;
	int i = 0;

	MAKE_STD_ZVAL(z_command);
	MAKE_STD_ZVAL(z_key);
	MAKE_STD_ZVAL(z_opts);
	
	ZVAL_STRING(z_command, "cas", 1);
	ZVAL_STRINGL(z_key, key, key_len, 1);
	array_init(z_opts);

	add_assoc_long_ex(z_opts, "flags", sizeof("flags"), flags);
	add_assoc_long_ex(z_opts, "exptime", sizeof("exptime"), exptime);
	add_assoc_stringl_ex(z_opts, "data", sizeof("data"), data, data_len, 1);
	add_assoc_long_ex(z_opts, "cas_unique", sizeof("cas_unique"), cas_unique);
	add_assoc_long_ex(z_opts, "noreply", sizeof("noreply"), noreply);
	
	params[0] = &z_command;
	params[1] = &z_key;
	params[2] = &z_opts;

	php_memcache_parser_do_callback(&retval, ctx, params, 3 TSRMLS_CC);

	if (retval != NULL) {
		zval_ptr_dtor(&retval);
	}
	
	zval_ptr_dtor(params[0]);
	zval_ptr_dtor(params[1]);
	zval_ptr_dtor(params[2]);
	
	return 0;
}

static int php_memcache_parser_delete(
		const char* key, unsigned key_len,
		uint64_t time, bool noreply,
		void* user)
{
	TSRMLS_FETCH();
	zval **params[3], *z_command, *z_key, *z_opts, *retval = NULL;
	php_memcache_parser_t *ctx = (php_memcache_parser_t*)user;
	int i = 0;

	MAKE_STD_ZVAL(z_command);
	MAKE_STD_ZVAL(z_key);
	MAKE_STD_ZVAL(z_opts);
	
	ZVAL_STRING(z_command, "delete", 1);
	ZVAL_STRINGL(z_key, key, key_len, 1);
	array_init(z_opts);

	add_assoc_long_ex(z_opts, "time", sizeof("time"), time);
	add_assoc_long_ex(z_opts, "noreply", sizeof("noreply"), noreply);
	
	params[0] = &z_command;
	params[1] = &z_key;
	params[2] = &z_opts;

	php_memcache_parser_do_callback(&retval, ctx, params, 3 TSRMLS_CC);

	if (retval != NULL) {
		zval_ptr_dtor(&retval);
	}
	
	zval_ptr_dtor(params[0]);
	zval_ptr_dtor(params[1]);
	zval_ptr_dtor(params[2]);
	
	return 0;
}

static int php_memcache_parser_quit(void* user)
{
	TSRMLS_FETCH();
	zval **params[3], *z_command, *z_key, *z_opts, *retval = NULL;
	php_memcache_parser_t *ctx = (php_memcache_parser_t*)user;
	int i = 0;

	MAKE_STD_ZVAL(z_command);
	MAKE_STD_ZVAL(z_key);
	MAKE_STD_ZVAL(z_opts);
	
	ZVAL_STRING(z_command, "quit", 1);
	ZVAL_NULL(z_key);
	array_init(z_opts);
	
	params[0] = &z_command;
	params[1] = &z_key;
	params[2] = &z_opts;

	php_memcache_parser_do_callback(&retval, ctx, params, 3 TSRMLS_CC);

	if (retval != NULL) {
		zval_ptr_dtor(&retval);
	}
	
	zval_ptr_dtor(params[0]);
	zval_ptr_dtor(params[1]);
	zval_ptr_dtor(params[2]);
	
	return 0;}

static inline void php_memcache_parser_cb_init(php_memcache_parser_t *ctx, zend_fcall_info *fci, zend_fcall_info_cache *fcc)
{
	php_memcache_parser_cb_t *cb;

	if (ctx->callback == NULL) {
		cb = emalloc(sizeof(php_memcache_parser_cb_t));
	} else {
		cb = ctx->callback;
		if (cb->fci.function_name != NULL) {
			zval_ptr_dtor(&cb->fci.function_name);
#if PHP_VERSION_ID >= 50300
			if (fci->object_ptr) {
				zval_ptr_dtor(&cb->fci.object_ptr);
			}
#endif
		}
	}

	memcpy(&cb->fci, fci, sizeof(zend_fcall_info));
	memcpy(&cb->fcc, fcc, sizeof(zend_fcall_info_cache));

	if (ZEND_FCI_INITIALIZED(*fci)) {
		Z_ADDREF_P(cb->fci.function_name);
#if PHP_VERSION_ID >= 50300
		if (fci->object_ptr) {
			Z_ADDREF_P(cb->fci.object_ptr);
		}
#endif
	}

	ctx->callback = cb;
}

PHP_MINIT_FUNCTION(memcache_parser) {
	memcache_parser_resource_handle = zend_register_list_destructors_ex(destruct_memcache_parser, NULL, PHP_MEMCACHE_PARSER_RESOURCE_NAME, module_number);

	return SUCCESS;
}

PHP_FUNCTION(memcache_parser_init)
{
	php_memcache_parser_t *ctx;
	memcache_parser_callback callback;

/*
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
		"|l",&target) == FAILURE) {
		return;
	}
*/
	
	callback.cmd_get     = php_memcache_parser_retrieval;
	callback.cmd_set     = php_memcache_parser_storage_set;
	callback.cmd_replace = php_memcache_parser_storage_replace;
	callback.cmd_append  = php_memcache_parser_storage_append;
	callback.cmd_prepend = php_memcache_parser_storage_prepend;
	callback.cmd_cas     = php_memcache_parser_cas;
	callback.cmd_delete  = php_memcache_parser_delete;
	callback.cmd_quit    = php_memcache_parser_quit;

	ctx = emalloc(sizeof(php_memcache_parser_t));
	ctx->finished = 1;
	ctx->callback = NULL;
	
	memcache_parser_init(&ctx->parser, &callback, (void*)ctx);
	ZEND_REGISTER_RESOURCE(return_value, ctx, memcache_parser_resource_handle);
}


PHP_FUNCTION(memcache_parser_execute)
{
	php_memcache_parser_t *ctx;
	zval *rsc;
	char *buffer;
	int result = 0, buffer_len = 0;
	zval *nread; /* do we need this? */
	size_t off;
	zend_fcall_info fci       = empty_fcall_info;
	zend_fcall_info_cache fcc = empty_fcall_info_cache;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
		"rszf", &rsc, &buffer, &buffer_len, &nread, &fci, &fcc) == FAILURE) {
		return;
	}

	ZEND_FETCH_RESOURCE(ctx, php_memcache_parser_t*, &rsc, -1, PHP_MEMCACHE_PARSER_RESOURCE_NAME, memcache_parser_resource_handle);

	if (Z_TYPE_P(nread) != IS_LONG) {
		convert_to_long(nread);
	}

	php_memcache_parser_cb_init(ctx, &fci, &fcc);

	off = Z_LVAL_P(nread);
	result = memcache_parser_execute(&ctx->parser, (const char*)buffer, buffer_len, &off);
	ZVAL_LONG(nread, (long)off);
	
	RETURN_LONG(result);
}

ZEND_BEGIN_ARG_INFO_EX(arginfo_memcache_parser_execute, 1, 0, 3)
	ZEND_ARG_INFO(0, resource)
	ZEND_ARG_INFO(0, buffer)
	ZEND_ARG_INFO(1, nread)
	ZEND_ARG_INFO(0, callback)
ZEND_END_ARG_INFO()

static zend_function_entry memcache_parser_functions[] = {
	PHP_FE(memcache_parser_init,    NULL)
	PHP_FE(memcache_parser_execute, arginfo_memcache_parser_execute)
	{NULL, NULL, NULL}
};


zend_module_entry memcache_parser_module_entry = {
#if ZEND_MODULE_API_NO >= 20010901
	STANDARD_MODULE_HEADER,
#endif
	"memcache_parser",
	memcache_parser_functions,					/* Functions */
	PHP_MINIT(memcache_parser),	/* MINIT */
	NULL,					/* MSHUTDOWN */
	NULL,					/* RINIT */
	NULL,					/* RSHUTDOWN */
	NULL,	/* MINFO */
#if ZEND_MODULE_API_NO >= 20010901
	PHP_MEMCACHE_PARSER_EXTVER,
#endif
	STANDARD_MODULE_PROPERTIES
};


#ifdef COMPILE_DL_MEMCACHE_PARSER
ZEND_GET_MODULE(memcache_parser)
#endif