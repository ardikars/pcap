/** This code is licenced under the GPL version 2. */
package pcap.api.internal.foreign.mapping;

import pcap.api.internal.foreign.win_pcap_header;

import java.foreign.Libraries;
import java.lang.invoke.MethodHandles;

/**
 * windows pcap native mapping.
 *
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 */
public final class WinPcapMapping {

  public static final win_pcap_header MAPPING;

  static {
    MAPPING =
        Libraries.bind(
                win_pcap_header.class, Libraries.loadLibrary(MethodHandles.lookup(), "wpcap"));
  }
}
