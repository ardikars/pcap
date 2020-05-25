module pcap.common {
  requires static org.apache.logging.log4j;
  requires static log4j;
  requires static org.slf4j;

  exports pcap.common.annotation;
  exports pcap.common.logging;
  exports pcap.common.memory;
  exports pcap.common.net;
  exports pcap.common.tuple;
  exports pcap.common.util;
  exports pcap.common.memory.internal to
      pcap.codec;
  exports pcap.common.memory.internal.nio to
      pcap.codec;
  exports pcap.common.memory.internal.allocator to
      pcap.codec;
}
