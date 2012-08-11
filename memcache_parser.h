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

#ifndef PHP_MEMCACHE_PARSER_H
#define PHP_MEMCACHE_PARSER_H

#define PHP_MEMCACHE_PARSER_EXTNAME "memcache_parser"
#define PHP_MEMCACHE_PARSER_EXTVER "0.1"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"

#include "ext/spl/spl_exceptions.h"
#include "zend_interfaces.h"

/* Define the entry point symbol
 * Zend will use when loading this module
 */
extern zend_module_entry memcache_parser_module_entry;
#define phpext_memcache_parser_ptr &memcache_parser_module_entry

#define PHP_MEMCACHE_PARSER_RESOURCE_NAME "memcache_parser"

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

#define MEMCACHE_PARSER_STACK_SIZE 256
#define MEMCACHE_PARSER_MAX_KEYS 256

typedef int (*memcache_parser_callback_retrieval)(
		const char** key, unsigned* key_len, unsigned keys,
		void* user);

typedef int (*memcache_parser_callback_storage)(
		const char* key, unsigned key_len,
		unsigned short flags, uint64_t exptime,
		const char* data, unsigned data_len,
		bool noreply,
		void* user);

typedef int (*memcache_parser_callback_cas)(
		const char* key, unsigned key_len,
		unsigned short flags, uint64_t exptime,
		const char* data, unsigned data_len,
		uint64_t cas_unique,
		bool noreply,
		void* user);

typedef int (*memcache_parser_callback_delete)(
		const char* key, unsigned key_len,
		uint64_t time, bool noreply,
		void* user);

typedef int (*memcache_parser_callback_quit)(void* user);

typedef struct {
	memcache_parser_callback_retrieval cmd_get;
	memcache_parser_callback_storage   cmd_set;
	memcache_parser_callback_storage   cmd_replace;
	memcache_parser_callback_storage   cmd_append;
	memcache_parser_callback_storage   cmd_prepend;
	memcache_parser_callback_cas       cmd_cas;
	memcache_parser_callback_delete    cmd_delete;
	memcache_parser_callback_quit      cmd_quit;
} memcache_parser_callback;

typedef struct {
	size_t data_count;

	int cs;
	int top;
	int stack[MEMCACHE_PARSER_STACK_SIZE];

	int command;

	size_t key_pos[MEMCACHE_PARSER_MAX_KEYS];
	unsigned int key_len[MEMCACHE_PARSER_MAX_KEYS];
	unsigned int keys;

	size_t flags;
	uint64_t exptime;
	size_t bytes;
	bool noreply;
	uint64_t time;
	uint64_t cas_unique;

	size_t data_pos;
	unsigned int data_len;

	memcache_parser_callback callback;

	void* user;
} memcache_parser;

void memcache_parser_init(memcache_parser* parser, memcache_parser_callback* callback, void* user);
int memcache_parser_execute(memcache_parser* parser, const char* data, size_t len, size_t* off);

typedef struct {
	zend_fcall_info fci;
	zend_fcall_info_cache fcc;
} php_memcache_parser_cb_t;

typedef struct {
	memcache_parser parser;
	zval *result;
	bool finished;
	php_memcache_parser_cb_t *callback;
} php_memcache_parser_t;

#endif /* PHP_MEMCACHE_PARSER_H */
