/** This code is licenced under the GPL version 2. */
package pcap.api.internal.foreign.mapping;

import java.foreign.Libraries;
import java.lang.invoke.MethodHandles;
import pcap.api.internal.foreign.darwin_pcap_header;

/**
 * Darwin pcap native mapping.
 *
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 */
public final class DarwinPcapMapping {

  public static final darwin_pcap_header MAPPING;

  static {
    MAPPING =
        Libraries.bind(
            darwin_pcap_header.class, Libraries.loadLibrary(MethodHandles.lookup(), "pcap"));
  }
}
