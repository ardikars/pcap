/** This code is licenced under the GPL version 2. */
package pcap.api.internal.foreign.mapping;

import java.foreign.Libraries;
import java.lang.invoke.MethodHandles;
import pcap.api.internal.foreign.unix_pcap_header;

/**
 * unix pcap native mapping.
 *
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 */
public final class UnixPcapMapping {

  public static final unix_pcap_header MAPPING;

  static {
    MAPPING =
        Libraries.bind(
            unix_pcap_header.class, Libraries.loadLibrary(MethodHandles.lookup(), "pcap"));
  }
}
