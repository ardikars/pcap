

## PCAP - API

Provides high level JVM network packet processing library for rapid development.


### Project status: INCUBATING

Add below configuration to your pom.xml

```
<repositories>
    <repository>
        <id>snaphot-repository</id>
        <url>https://oss.sonatype.org/content/repositories/snapshots</url>
        <snapshots>
            <enabled>true</enabled>
        </snapshots>
        <releases>
            <enabled>false</enabled>
        </releases>
    </repository>
</repositories>

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
            <version>0.0.3-SNAPSHOT</version>
            <type>pom</type>
            <scope>import</scope>
        </dependency>
    </dependencies>
</dependencyManagement>
```