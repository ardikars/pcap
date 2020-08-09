/** This code is licenced under the GPL version 2. */
package pcap.api.internal.foreign.mapping;

import java.foreign.Libraries;
import java.lang.invoke.MethodHandles;
import pcap.api.internal.foreign.windows_pcap_header;

/**
 * Windows pcap native mapping.
 *
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 */
public final class WindowsPcapMapping {

  public static final windows_pcap_header MAPPING;

  static {
    MAPPING =
        Libraries.bind(
            windows_pcap_header.class, Libraries.loadLibrary(MethodHandles.lookup(), "wpcap"));
  }
}
