:: SPDX-FileCopyrightText: 2020 Pcap <contact@pcap.ardikars.com>
:: SPDX-License-Identifier: MIT

mvnw.cmd -t .mvn/toolchains.xml clean install jacoco:report-aggregate -Pcoverage -Pformat -Pjavadoc -Plegacy-support -Djna.library.path="C:\Windows\System32\Npcap"
