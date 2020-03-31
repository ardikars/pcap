#!/bin/bash

cp .mvn/toolchains.xml ~/.m2

export JAVA_HOME_8="/Volumes/Data/Application/jdk8u222-b10/Contents/Home"
export JAVA_HOME_14="/Volumes/Data/Application/jdk-14.jdk/Contents/Home"
export JAVA_HOME=${JAVA_HOME_14}

./mvnw clean install -Plegacy-support -Pformat -DskipTests