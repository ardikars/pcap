module pcap.common {

    requires java.logging;
    requires org.apache.logging.log4j;
    requires log4j;
    requires org.slf4j;
    requires jdk.unsupported;

    exports pcap.common.memory;
    exports pcap.common.net;
    exports pcap.common.util;
    exports pcap.common.logging;

}
