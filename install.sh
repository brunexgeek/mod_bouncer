#!/bin/bash -x

DIR=$(cd $(dirname $0) && pwd)
apxs -i -a \
-Wl,-fvisibility=hidden \
-Wl,--no-undefined \
-n bouncer \
mod_bouncer.la