# SPDX-FileCopyrightText: 2020-2021 Pcap Project
# SPDX-License-Identifier: MIT OR Apache-2.0

#!/bin/bash

# Run from root project $ ./.mvn/install-local.sh
#
#unameOut="$(uname -s)"
#case "${unameOut}" in
#    Linux*)     machine=Linux;;
#    Darwin*)    machine=Mac;;
#    *)          machine="UNKNOWN:${unameOut}"
#esac
#
#if [ "$machine" == "Linux" ]; then
#  export JAVA_HOME_JDK7="/usr/lib/jvm/jdk-8"
#  export JAVA_HOME="/usr/lib/jvm/jdk-11"
#elif [ "$machine" == "Mac" ]; then
#  export JAVA_HOME_JDK7="/Library/Java/JavaVirtualMachines/jdk-8/Contents/Home"
#  export JAVA_HOME="/Library/Java/JavaVirtualMachines/jdk-11/Contents/Home"
#fi
#
#export PATH=$JAVA_HOME/bin:$PATH

sudo -E bash -c './mvnw -t .mvn/toolchains.xml clean install jacoco:report-aggregate -Pcoverage -Pformat -Plegacy-support'
