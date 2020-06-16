module pcap.common {
  requires org.apache.logging.log4j;
  requires log4j;
  requires org.slf4j;

  exports pcap.common.annotation;
  exports pcap.common.logging;
  exports pcap.common.memory;
  exports pcap.common.net;
  exports pcap.common.util;
  exports pcap.common.memory.internal to
      pcap.codec;
  exports pcap.common.memory.internal.nio to
      pcap.codec;
  exports pcap.common.memory.internal.allocator to
      pcap.codec;
}
