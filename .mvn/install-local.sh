#!/bin/bash

# Run from root project $ ./.mvn/install-local.sh

unameOut="$(uname -s)"
case "${unameOut}" in
    Linux*)     machine=Linux;;
    Darwin*)    machine=Mac;;
    *)          machine="UNKNOWN:${unameOut}"
esac

if [ "$machine" == "Linux" ]; then
  export JAVA_HOME_8="/usr/lib/jvm/java-8-openjdk-amd64"
  export JAVA_HOME="/usr/lib/jvm/jdk-14"

  echo "You must enable sudo without password for ($(whoami)) in your sudoers config."
  sudo setcap cap_net_raw,cap_net_admin=eip $JAVA_HOME_8/jre/bin/java
  sudo setcap cap_net_raw,cap_net_admin=eip $JAVA_HOME/bin/java
elif [ "$machine" == "Mac" ]; then
  export JAVA_HOME_8="/Volumes/Data/Application/jdk8u222-b10/Contents/Home"
  export JAVA_HOME="/Library/Java/JavaVirtualMachines/jdk-14.jdk/Contents/Home/"
fi

export PATH=$JAVA_HOME/bin:$PATH

./mvnw -t .mvn/toolchains.xml clean install jacoco:report-aggregate -Pcoverage -Pformat -Pjavadoc
