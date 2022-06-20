#!/bin/bash -x

DIR=$(cd $(dirname $0) && pwd)
apxs \
-Wc,-pedantic \
-Wc,-Wall \
-Wc,-Wextra \
-Wc,-Wconversion \
-Wc,-Werror=return-type \
-Wc,-Werror=implicit-function-declaration \
-Wl,-fvisibility=hidden \
-Wl,--no-undefined \
-Wc,-Wfatal-errors \
-c $DIR/mod_bouncer.c -c $DIR/dfa.c -c $DIR/log.c
