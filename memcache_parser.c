
#line 1 "memcache_parser.rl"
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
};


#line 259 "memcache_parser.rl"




#line 83 "memcache_parser.c"
static const char _memcache_parser_actions[] = {
	0, 1, 0, 1, 1, 1, 2, 1, 
	4, 1, 5, 1, 6, 1, 7, 1, 
	8, 1, 9, 1, 10, 1, 11, 1, 
	12, 1, 13, 1, 14, 1, 15, 1, 
	16, 1, 17, 1, 18, 1, 19, 1, 
	20, 1, 21, 1, 22, 1, 23, 1, 
	24, 1, 25, 1, 26, 1, 27, 2, 
	3, 1
};

static const unsigned char _memcache_parser_key_offsets[] = {
	0, 0, 7, 8, 9, 10, 11, 12, 
	13, 15, 18, 21, 22, 25, 26, 28, 
	32, 33, 34, 35, 36, 37, 38, 40, 
	43, 46, 47, 50, 51, 53, 56, 59, 
	61, 62, 63, 64, 65, 66, 67, 68, 
	69, 70, 71, 72, 76, 79, 82, 83, 
	84, 85, 86, 87, 88, 90, 94, 95, 
	99, 101, 102, 103, 104, 105, 106, 107, 
	108, 109, 113, 114, 115, 117, 119, 123, 
	124, 126, 127, 128, 129, 130, 131, 132, 
	133, 134, 135, 136, 137, 138, 139, 140, 
	141, 142, 143, 144, 145, 146, 147, 148, 
	149, 152, 155, 162
};

static const char _memcache_parser_trans_keys[] = {
	97, 99, 100, 103, 112, 114, 115, 112, 
	112, 101, 110, 100, 32, 33, 126, 32, 
	33, 126, 48, 49, 57, 32, 48, 49, 
	57, 32, 49, 57, 13, 32, 48, 57, 
	10, 13, 10, 97, 115, 32, 33, 126, 
	32, 33, 126, 48, 49, 57, 32, 48, 
	49, 57, 32, 49, 57, 32, 48, 57, 
	48, 49, 57, 13, 32, 10, 13, 10, 
	110, 111, 114, 101, 112, 108, 121, 13, 
	13, 32, 48, 57, 32, 48, 57, 32, 
	48, 57, 101, 108, 101, 116, 101, 32, 
	33, 126, 13, 32, 33, 126, 10, 48, 
	110, 49, 57, 13, 32, 110, 111, 114, 
	101, 112, 108, 121, 13, 13, 32, 48, 
	57, 101, 116, 32, 115, 33, 126, 13, 
	32, 33, 126, 10, 33, 126, 32, 114, 
	101, 112, 101, 110, 100, 101, 112, 108, 
	97, 99, 101, 101, 116, 110, 111, 114, 
	101, 112, 108, 121, 13, 32, 48, 57, 
	32, 48, 57, 97, 99, 100, 103, 112, 
	114, 115, 0
};

static const char _memcache_parser_single_lengths[] = {
	0, 7, 1, 1, 1, 1, 1, 1, 
	0, 1, 1, 1, 1, 1, 0, 2, 
	1, 1, 1, 1, 1, 1, 0, 1, 
	1, 1, 1, 1, 0, 1, 1, 2, 
	1, 1, 1, 1, 1, 1, 1, 1, 
	1, 1, 1, 2, 1, 1, 1, 1, 
	1, 1, 1, 1, 0, 2, 1, 2, 
	2, 1, 1, 1, 1, 1, 1, 1, 
	1, 2, 1, 1, 2, 0, 2, 1, 
	0, 1, 1, 1, 1, 1, 1, 1, 
	1, 1, 1, 1, 1, 1, 1, 1, 
	1, 1, 1, 1, 1, 1, 1, 1, 
	1, 1, 7, 0
};

static const char _memcache_parser_range_lengths[] = {
	0, 0, 0, 0, 0, 0, 0, 0, 
	1, 1, 1, 0, 1, 0, 1, 1, 
	0, 0, 0, 0, 0, 0, 1, 1, 
	1, 0, 1, 0, 1, 1, 1, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 1, 1, 1, 0, 0, 
	0, 0, 0, 0, 1, 1, 0, 1, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 1, 0, 0, 0, 1, 1, 0, 
	1, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	1, 1, 0, 0
};

static const short _memcache_parser_index_offsets[] = {
	0, 0, 8, 10, 12, 14, 16, 18, 
	20, 22, 25, 28, 30, 33, 35, 37, 
	41, 43, 45, 47, 49, 51, 53, 55, 
	58, 61, 63, 66, 68, 70, 73, 76, 
	79, 81, 83, 85, 87, 89, 91, 93, 
	95, 97, 99, 101, 105, 108, 111, 113, 
	115, 117, 119, 121, 123, 125, 129, 131, 
	135, 138, 140, 142, 144, 146, 148, 150, 
	152, 154, 158, 160, 162, 165, 167, 171, 
	173, 175, 177, 179, 181, 183, 185, 187, 
	189, 191, 193, 195, 197, 199, 201, 203, 
	205, 207, 209, 211, 213, 215, 217, 219, 
	221, 224, 227, 235
};

static const char _memcache_parser_trans_targs[] = {
	2, 19, 46, 66, 74, 80, 86, 0, 
	3, 0, 4, 0, 5, 0, 6, 0, 
	7, 0, 8, 0, 9, 0, 10, 9, 
	0, 11, 97, 0, 12, 0, 13, 96, 
	0, 14, 0, 15, 0, 16, 88, 15, 
	0, 17, 0, 18, 0, 98, 0, 20, 
	0, 21, 0, 22, 0, 23, 0, 24, 
	23, 0, 25, 45, 0, 26, 0, 27, 
	44, 0, 28, 0, 29, 0, 30, 29, 
	0, 31, 43, 0, 32, 35, 0, 33, 
	0, 34, 0, 98, 0, 36, 0, 37, 
	0, 38, 0, 39, 0, 40, 0, 41, 
	0, 42, 0, 32, 0, 32, 35, 43, 
	0, 28, 44, 0, 26, 45, 0, 47, 
	0, 48, 0, 49, 0, 50, 0, 51, 
	0, 52, 0, 53, 0, 54, 55, 53, 
	0, 98, 0, 56, 58, 65, 0, 54, 
	57, 0, 58, 0, 59, 0, 60, 0, 
	61, 0, 62, 0, 63, 0, 64, 0, 
	54, 0, 54, 57, 65, 0, 67, 0, 
	68, 0, 69, 73, 0, 70, 0, 71, 
	72, 70, 0, 98, 0, 70, 0, 69, 
	0, 75, 0, 76, 0, 77, 0, 78, 
	0, 79, 0, 7, 0, 81, 0, 82, 
	0, 83, 0, 84, 0, 85, 0, 7, 
	0, 87, 0, 7, 0, 89, 0, 90, 
	0, 91, 0, 92, 0, 93, 0, 94, 
	0, 95, 0, 16, 0, 14, 96, 0, 
	12, 97, 0, 2, 19, 46, 66, 74, 
	80, 86, 0, 99, 0
};

static const char _memcache_parser_trans_actions[] = {
	1, 1, 1, 1, 1, 1, 1, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	39, 0, 0, 0, 3, 0, 5, 0, 
	0, 7, 7, 0, 9, 0, 11, 11, 
	0, 13, 0, 15, 0, 17, 17, 0, 
	0, 29, 0, 0, 0, 49, 0, 0, 
	0, 43, 0, 0, 0, 3, 0, 5, 
	0, 0, 7, 7, 0, 9, 0, 11, 
	11, 0, 13, 0, 15, 0, 17, 0, 
	0, 25, 25, 0, 27, 27, 0, 29, 
	0, 0, 0, 51, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 19, 0, 27, 27, 0, 
	0, 13, 0, 0, 9, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 45, 
	0, 0, 0, 3, 0, 5, 5, 0, 
	0, 53, 0, 21, 0, 21, 0, 23, 
	23, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	19, 0, 23, 23, 0, 0, 0, 0, 
	33, 0, 0, 33, 0, 3, 0, 5, 
	5, 0, 0, 47, 0, 55, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 41, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 37, 
	0, 0, 0, 35, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 19, 0, 13, 0, 0, 
	9, 0, 0, 1, 1, 1, 1, 1, 
	1, 1, 0, 31, 0
};

static const int memcache_parser_start = 1;
static const int memcache_parser_first_final = 98;
static const int memcache_parser_error = 0;

static const int memcache_parser_en_main = 1;
static const int memcache_parser_en_data = 99;


#line 263 "memcache_parser.rl"

void memcache_parser_init(memcache_parser* parser, memcache_parser_callback* callback, void* user)
{
	int cs = 0;
	int top = 0;
	
#line 264 "memcache_parser.c"
	{
	cs = memcache_parser_start;
	top = 0;
	}

#line 269 "memcache_parser.rl"
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

	
#line 298 "memcache_parser.c"
	{
	int _klen;
	unsigned int _trans;
	const char *_acts;
	unsigned int _nacts;
	const char *_keys;

	if ( p == pe )
		goto _test_eof;
	if ( cs == 0 )
		goto _out;
_resume:
	_keys = _memcache_parser_trans_keys + _memcache_parser_key_offsets[cs];
	_trans = _memcache_parser_index_offsets[cs];

	_klen = _memcache_parser_single_lengths[cs];
	if ( _klen > 0 ) {
		const char *_lower = _keys;
		const char *_mid;
		const char *_upper = _keys + _klen - 1;
		while (1) {
			if ( _upper < _lower )
				break;

			_mid = _lower + ((_upper-_lower) >> 1);
			if ( (*p) < *_mid )
				_upper = _mid - 1;
			else if ( (*p) > *_mid )
				_lower = _mid + 1;
			else {
				_trans += (_mid - _keys);
				goto _match;
			}
		}
		_keys += _klen;
		_trans += _klen;
	}

	_klen = _memcache_parser_range_lengths[cs];
	if ( _klen > 0 ) {
		const char *_lower = _keys;
		const char *_mid;
		const char *_upper = _keys + (_klen<<1) - 2;
		while (1) {
			if ( _upper < _lower )
				break;

			_mid = _lower + (((_upper-_lower) >> 1) & ~1);
			if ( (*p) < _mid[0] )
				_upper = _mid - 2;
			else if ( (*p) > _mid[1] )
				_lower = _mid + 2;
			else {
				_trans += ((_mid - _keys)>>1);
				goto _match;
			}
		}
		_trans += _klen;
	}

_match:
	cs = _memcache_parser_trans_targs[_trans];

	if ( _memcache_parser_trans_actions[_trans] == 0 )
		goto _again;

	_acts = _memcache_parser_actions + _memcache_parser_trans_actions[_trans];
	_nacts = (unsigned int) *_acts++;
	while ( _nacts-- > 0 )
	{
		switch ( *_acts++ )
		{
	case 0:
#line 77 "memcache_parser.rl"
	{
		parser->keys = 0;
		parser->noreply = false;
		parser->time = 0;
	}
	break;
	case 1:
#line 83 "memcache_parser.rl"
	{
		MARK(key_pos[parser->keys], p);
	}
	break;
	case 2:
#line 86 "memcache_parser.rl"
	{
		SET_MARK_LEN(key_len[parser->keys], key_pos[parser->keys], p);
	}
	break;
	case 3:
#line 89 "memcache_parser.rl"
	{
		++parser->keys;
	}
	break;
	case 4:
#line 93 "memcache_parser.rl"
	{
		MARK(flags, p);
	}
	break;
	case 5:
#line 96 "memcache_parser.rl"
	{
		SET_UINT(flags, flags, p);
	}
	break;
	case 6:
#line 100 "memcache_parser.rl"
	{
		MARK(exptime, p);
	}
	break;
	case 7:
#line 103 "memcache_parser.rl"
	{
		SET_ULL(exptime, exptime, p);
	}
	break;
	case 8:
#line 107 "memcache_parser.rl"
	{
		MARK(bytes, p);
	}
	break;
	case 9:
#line 110 "memcache_parser.rl"
	{
		SET_UINT(bytes, bytes, p);
	}
	break;
	case 10:
#line 114 "memcache_parser.rl"
	{
		parser->noreply = true;
	}
	break;
	case 11:
#line 118 "memcache_parser.rl"
	{
		MARK(time, p);
	}
	break;
	case 12:
#line 121 "memcache_parser.rl"
	{
		SET_ULL(time, time, p);
	}
	break;
	case 13:
#line 125 "memcache_parser.rl"
	{
		MARK(cas_unique, p);
	}
	break;
	case 14:
#line 128 "memcache_parser.rl"
	{
		SET_ULL(cas_unique, cas_unique, p);
	}
	break;
	case 15:
#line 132 "memcache_parser.rl"
	{
		MARK(data_pos, p+1);
		parser->data_count = parser->bytes;
		{stack[top++] = cs; cs = 99; goto _again;}
	}
	break;
	case 16:
#line 137 "memcache_parser.rl"
	{
		if(--parser->data_count == 0) {
			//printf("mark %d\n", parser->data_pos);
			//printf("fpc %p\n", fpc);
			//printf("data %p\n", data);
			SET_MARK_LEN(data_len, data_pos, p+1);
			{cs = stack[--top]; goto _again;}
		}
	}
	break;
	case 17:
#line 148 "memcache_parser.rl"
	{ parser->command = CMD_GET;     }
	break;
	case 18:
#line 150 "memcache_parser.rl"
	{ parser->command = CMD_SET;     }
	break;
	case 19:
#line 151 "memcache_parser.rl"
	{ parser->command = CMD_REPLACE; }
	break;
	case 20:
#line 152 "memcache_parser.rl"
	{ parser->command = CMD_APPEND;  }
	break;
	case 21:
#line 153 "memcache_parser.rl"
	{ parser->command = CMD_PREPEND; }
	break;
	case 22:
#line 155 "memcache_parser.rl"
	{ parser->command = CMD_CAS;     }
	break;
	case 23:
#line 157 "memcache_parser.rl"
	{ parser->command = CMD_DELETE;  }
	break;
	case 24:
#line 160 "memcache_parser.rl"
	{
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
	break;
	case 25:
#line 172 "memcache_parser.rl"
	{
		if( CALLBACK(command, memcache_parser_callback_storage)(
				MARK_PTR(key_pos[0]), parser->key_len[0],
				parser->flags,
				parser->exptime,
				MARK_PTR(data_pos), parser->data_len,
				parser->noreply,
				parser->user
				) < -1 ) { goto convert_error; }
	}
	break;
	case 26:
#line 183 "memcache_parser.rl"
	{
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
	break;
	case 27:
#line 195 "memcache_parser.rl"
	{
		if( CALLBACK(command, memcache_parser_callback_delete)(
				MARK_PTR(key_pos[0]), parser->key_len[0],
				parser->time, parser->noreply,
				parser->user
				) < -1 ) { goto convert_error; }
	}
	break;
#line 562 "memcache_parser.c"
		}
	}

_again:
	if ( cs == 0 )
		goto _out;
	if ( ++p != pe )
		goto _resume;
	_test_eof: {}
	_out: {}
	}

#line 296 "memcache_parser.rl"

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

	ctx = emalloc(sizeof(php_memcache_parser_t));
	ctx->finished = false;
	
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