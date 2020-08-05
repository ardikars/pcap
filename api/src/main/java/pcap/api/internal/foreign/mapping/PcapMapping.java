/** This code is licenced under the GPL version 2. */
package pcap.api.internal.foreign.mapping;

import java.foreign.Libraries;
import java.lang.invoke.MethodHandles;
import pcap.api.internal.foreign.pcap_header;
import pcap.common.annotation.Inclubating;
import pcap.common.util.Platforms;

/**
 * Variable holder
 *
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 */
@Inclubating
public final class PcapMapping {

  public static final int OK = 0;
  public static final Object LOCK = new Object();
  public static final int ERRBUF_SIZE = 256;
  public static final pcap_header MAPPING;

  static {
    MAPPING =
        Libraries.bind(
            pcap_header.class,
            Libraries.loadLibrary(
                MethodHandles.lookup(), Platforms.isWindows() ? "wpcap" : "pcap"));
  }

  private PcapMapping() {}
}
