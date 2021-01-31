:: SPDX-FileCopyrightText: 2020-2021 Pcap Project
:: SPDX-License-Identifier: MIT OR Apache-2.0

mvnw.cmd -t .mvn/toolchains.xml clean install jacoco:report-aggregate -Pcoverage -Pformat -Pjavadoc -Plegacy-support -Djna.library.path="C:\Windows\System32\Npcap"
