/** This code is licenced under the GPL version 2. */

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
module pcap.common {
  requires net.bytebuddy;
  requires org.apache.logging.log4j;
  requires log4j;
  requires org.slf4j;
  requires jdk.unsupported;

  exports pcap.common.annotation;
  exports pcap.common.memory;
  exports pcap.common.net;
  exports pcap.common.util;
  exports pcap.common.tuple;
  exports pcap.common.logging;
}
