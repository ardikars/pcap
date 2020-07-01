/** This code is licenced under the GPL version 2. */
package pcap.api.internal;

import java.foreign.Libraries;
import java.foreign.Library;
import java.lang.invoke.MethodHandles;
import pcap.api.internal.foreign.pcap_mapping;
import pcap.common.annotation.Inclubating;
import pcap.common.util.Platforms;

/**
 * Variable holder
 *
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 */
@Inclubating
public final class PcapConstant {

  public static final int OK = 0;
  public static final Object LOCK = new Object();
  public static final int ERRBUF_SIZE = 256;
  public static final pcap_mapping MAPPING;

  static {
    MethodHandles.Lookup lookup = MethodHandles.lookup();
    Library library = Libraries.loadLibrary(lookup, Platforms.isWindows() ? "wpcap" : "pcap");
    MAPPING = Libraries.bind(pcap_mapping.class, library);
  }

  private PcapConstant() {}
}
