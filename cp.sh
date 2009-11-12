#!/bin/bash

export CLASSPATH=

for i in lib/*.jar; do
	CLASSPATH=`pwd`/$i:$CLASSPATH
done

CLASSPATH=/home/yacin/src/clojure/clojure.jar:/home/yacin/src/clojure-contrib/clojure-contrib.jar:$CLASSPATH

export CLASSPATH
