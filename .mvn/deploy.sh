#!/bin/bash

JAVA_8="/Volumes/Data/Application/jdk8u222-b10/Contents/Home"
JAVA_14="/Volumes/Data/Application/jdk-14.jdk/Contents/Home"
export JAVA_HOME=$JAVA_8
java_version=$(mvn --version | grep 'Java version')
java_version=${java_version:14:2}
if [ $java_version != '1.' ]
then
  echo "Invalid java version: $JAVA_HOME"
  exit
fi

sleep 1

export JAVA_HOME=$JAVA_14
java_version=$(mvn --version | grep 'Java version')
java_version=${java_version:14:2}
if [ $java_version != '14' ]
then
  echo "Invalid java version: $JAVA_HOME"
  exit
fi

export JAVA_HOME=$JAVA_8
echo ""
echo "Deploying..."
java -version
./mvnw clean deploy -pl !api -Plegacy-support,release
sleep 1

export JAVA_HOME=$JAVA_14
java -version
./mvnw clean deploy -pl api -Prelease
echo "Finished."
