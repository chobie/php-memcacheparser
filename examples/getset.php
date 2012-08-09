<?php

$parser = memcache_parser_init();
$parser2 = memcache_parser_init();

$msgs[] = "set aaa 0 0 10\r\nabcdefghij\r\n";
$msgs[] = "get aaa \r\n";

$nread = 0;
foreach($msgs as $msg) {
    memcache_parser_execute($parser, $msg, $nread, function($command, $key, $options){
        switch ($command) {
            case "get":
                var_dump($key);
                var_dump($options);
                break;
            case "set":
                var_dump($key);
                var_dump($options);
                break;
            default:
                echo "not supported";
                break;
        }
    });
}
