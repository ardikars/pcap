/** This code is licenced under the GPL version 2. */
package pcap.api.internal.foreign.mapping;

import java.foreign.Libraries;
import java.lang.invoke.MethodHandles;
import pcap.api.internal.foreign.iphlpapi_header;

/**
 * Windows native mapping.
 *
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 */
public final class IphlpapiMapping {

  public static final iphlpapi_header MAPPING;

  static {
    MAPPING =
        Libraries.bind(
            iphlpapi_header.class, Libraries.loadLibrary(MethodHandles.lookup(), "iphlpapi"));
  }

  private IphlpapiMapping() {}
}
