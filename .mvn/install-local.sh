#!/bin/bash

# Run from root project $ ./.mvn/install-local.sh

#export JAVA_HOME_8="/Volumes/Data/Application/jdk8u222-b10/Contents/Home"
#export JAVA_HOME_14="/Volumes/Data/Application/jdk-14.jdk/Contents/Home"
export JAVA_HOME_8="/usr/lib/jvm/java-8-openjdk-amd64"
export JAVA_HOME_14="/usr/lib/jvm/jdk-14"
export PATH=$JAVA_HOME_14/bin:$PATH
./mvnw -t .mvn/toolchains.xml clean install -Plegacy-support -Pformat -DskipTests
