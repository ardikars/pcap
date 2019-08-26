module pcap.codec {

    requires pcap.common;

    exports pcap.codec;
    exports pcap.codec.arp;
    exports pcap.codec.ethernet;
    exports pcap.codec.icmp;
    exports pcap.codec.icmp.icmp4;
    exports pcap.codec.icmp.icmp6;
    exports pcap.codec.ip;
    exports pcap.codec.ip.ip6;
    exports pcap.codec.ndp;
    exports pcap.codec.tcp;
    exports pcap.codec.udp;

}
