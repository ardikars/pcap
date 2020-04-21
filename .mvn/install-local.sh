#!/bin/bash

# Run from root project $ ./.mvn/install-local.sh

export JAVA_HOME_8="/Volumes/Data/Application/jdk8u222-b10/Contents/Home"
export JAVA_HOME_14="/Volumes/Data/Application/jdk-14.jdk/Contents/Home"
export JAVA_HOME=${JAVA_HOME_14}

./mvnw -t .mvn/toolchains.xml clean install -Plegacy-support -Pformat -DskipTests
