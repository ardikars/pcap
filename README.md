

## PCAP - API

Provides high level JVM network packet processing library for rapid development.

[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=com.ardikars.pcap%3Apcap&metric=alert_status)](https://sonarcloud.io/dashboard?id=com.ardikars.pcap%3Apcap)
[![Coverage](https://sonarcloud.io/api/project_badges/measure?project=com.ardikars.pcap%3Apcap&metric=coverage)](https://sonarcloud.io/dashboard?id=com.ardikars.pcap%3Apcap)
[![Code Smells](https://sonarcloud.io/api/project_badges/measure?project=com.ardikars.pcap%3Apcap&metric=code_smells)](https://sonarcloud.io/dashboard?id=com.ardikars.pcap%3Apcap)
[![Duplicated Lines (%)](https://sonarcloud.io/api/project_badges/measure?project=com.ardikars.pcap%3Apcap&metric=duplicated_lines_density)](https://sonarcloud.io/dashboard?id=com.ardikars.pcap%3Apcap)
[![Maintainability Rating](https://sonarcloud.io/api/project_badges/measure?project=com.ardikars.pcap%3Apcap&metric=sqale_rating)](https://sonarcloud.io/dashboard?id=com.ardikars.pcap%3Apcap)
[![Reliability Rating](https://sonarcloud.io/api/project_badges/measure?project=com.ardikars.pcap%3Apcap&metric=reliability_rating)](https://sonarcloud.io/dashboard?id=com.ardikars.pcap%3Apcap)
[![Security Rating](https://sonarcloud.io/api/project_badges/measure?project=com.ardikars.pcap%3Apcap&metric=security_rating)](https://sonarcloud.io/dashboard?id=com.ardikars.pcap%3Apcap)
[![Technical Debt](https://sonarcloud.io/api/project_badges/measure?project=com.ardikars.pcap%3Apcap&metric=sqale_index)](https://sonarcloud.io/dashboard?id=com.ardikars.pcap%3Apcap)
[![Lines of Code](https://sonarcloud.io/api/project_badges/measure?project=com.ardikars.pcap%3Apcap&metric=ncloc)](https://sonarcloud.io/dashboard?id=com.ardikars.pcap%3Apcap)
[![Bugs](https://sonarcloud.io/api/project_badges/measure?project=com.ardikars.pcap%3Apcap&metric=bugs)](https://sonarcloud.io/dashboard?id=com.ardikars.pcap%3Apcap)
[![Vulnerabilities](https://sonarcloud.io/api/project_badges/measure?project=com.ardikars.pcap%3Apcap&metric=vulnerabilities)](https://sonarcloud.io/dashboard?id=com.ardikars.pcap%3Apcap)

### How to build

- Install libpcap/npcap (for Windows)
- Install JDK 8 and JDK 14 (with Panama EA)

```shell script
export JAVA_HOME_8=<PATH TO JDK 8>
export JAVA_HOME_14=<PATH TO JDK 14 (with Panama EA)>
exprrt JAVA_HOME=${JAVA_HOME_14}
./mvnw -B -t .mvn/toolchains.xml clean package jacoco:report-aggregate -Pcoverage -Plegacy-support -Pformat
```

Please create an issue here on Github if there is error when building on your environment



### Project status: INCUBATING

Add below configuration to your pom.xml

```
<dependencies>
    <dependency>
        <groupId>com.ardikars.pcap</groupId>
        <artifactId>pcap-codec</artifactId>
    </dependency>
    <dependency>
        <groupId>com.ardikars.pcap</groupId>
        <artifactId>pcap-api</artifactId>
    </dependency>
</dependencies>

<dependencyManagement>
    <dependencies>
        <dependency>
            <groupId>com.ardikars.pcap</groupId>
            <artifactId>pcap</artifactId>
            <version>${PCAP-LATEST-VERSION}</version>
            <type>pom</type>
            <scope>import</scope>
        </dependency>
    </dependencies>
</dependencyManagement>
```