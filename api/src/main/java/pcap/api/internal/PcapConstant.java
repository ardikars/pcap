package pcap.api.internal;

import java.foreign.Libraries;
import java.foreign.Library;
import java.foreign.Scope;
import java.lang.invoke.MethodHandles;
import pcap.api.internal.foreign.pcap_mapping;
import pcap.common.annotation.Inclubating;
import pcap.common.util.Platforms;

@Inclubating
public final class PcapConstant {

  private PcapConstant() {}

  public static final int OK = 0;

  public static final Object LOCK = new Object();

  public static final int ERRBUF_SIZE = 256;

  public static final pcap_mapping MAPPING;

  public static final Scope SCOPE;

  static {
    MethodHandles.Lookup lookup = MethodHandles.lookup();
    Library library = Libraries.loadLibrary(lookup, Platforms.isWindows() ? "wpcap" : "pcap");
    MAPPING = Libraries.bind(pcap_mapping.class, library);
    SCOPE = Libraries.libraryScope(MAPPING);
  }
}
