## PCAP - API
[![FOSSA Status](https://app.fossa.io/api/projects/git%2Bgithub.com%2Fardikars%2Fpcap.svg?type=shield)](https://app.fossa.io/projects/git%2Bgithub.com%2Fardikars%2Fpcap?ref=badge_shield)


Provides high level JVM network packet processing library for rapid development.


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

## License
[![FOSSA Status](https://app.fossa.io/api/projects/git%2Bgithub.com%2Fardikars%2Fpcap.svg?type=large)](https://app.fossa.io/projects/git%2Bgithub.com%2Fardikars%2Fpcap?ref=badge_large)