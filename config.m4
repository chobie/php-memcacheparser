PHP_ARG_ENABLE(memcache_parser, Whether to enable the "memcache_parser" extension,
	[  --enable-memcache_parser      Enable "php-memcache_parser" extension support])

if test $PHP_MEMCACHE_PARSER != "no"; then
	PHP_SUBST(MEMCACHE_PARSER_SHARED_LIBADD)
	PHP_NEW_EXTENSION(memcache_parser, memcache_parser.c , $ext_shared)

	CFLAGS=" $CFLAGS -Wunused-variable -Wpointer-sign -Wimplicit-function-declaration -Winline -Wunused-macros -Wredundant-decls -Wstrict-aliasing=2 -Wswitch-enum -Wdeclaration-after-statement"
	PHP_SUBST([CFLAGS])
fi
