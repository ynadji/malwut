#!/bin/bash

export CLASSPATH=

for i in lib/*.jar; do
	CLASSPATH=`pwd`/$i:$CLASSPATH
done

CLASSPATH=~/src/clojure/clojure.jar:~/src/clojure-contrib/clojure-contrib.jar:$CLASSPATH

export CLASSPATH
