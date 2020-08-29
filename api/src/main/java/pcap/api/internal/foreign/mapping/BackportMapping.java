package pcap.api.internal.foreign.mapping;

import java.foreign.Libraries;
import java.lang.invoke.MethodHandles;
import pcap.api.internal.foreign.backport_pcap_header;
import pcap.api.internal.util.Platforms;

public class BackportMapping {

  public static final backport_pcap_header.linux LINUX_PCAP_MAPPING;
  public static final backport_pcap_header.darwin DARWIN_PCAP_MAPPING;

  static {
    backport_pcap_header.linux linux_mapping = null;
    backport_pcap_header.darwin darwin_mapping = null;
    switch (Platforms.name()) {
      case LINUX:
        linux_mapping =
            Libraries.bind(
                backport_pcap_header.linux.class,
                Libraries.loadLibrary(MethodHandles.lookup(), "pcap"));
        break;
      case DARWIN:
        darwin_mapping =
            Libraries.bind(
                backport_pcap_header.darwin.class,
                Libraries.loadLibrary(MethodHandles.lookup(), "pcap"));
        break;
    }
    LINUX_PCAP_MAPPING = linux_mapping;
    DARWIN_PCAP_MAPPING = darwin_mapping;
  }
}
