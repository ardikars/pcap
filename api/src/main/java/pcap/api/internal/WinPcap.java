/** This code is licenced under the GPL version 2. */
package pcap.api.internal;

import java.foreign.memory.Pointer;

import pcap.api.internal.foreign.mapping.WinPcapMapping;
import pcap.api.internal.foreign.pcap_header;

/**
 * Windows {@code Pcap} handle.
 *
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 */
public class WinPcap extends Pcap implements pcap.spi.Pcap.WinPcap {

  public WinPcap(Pointer<pcap_header.pcap> pcap) {
    super(pcap);
  }

  public WinPcap(Pointer<pcap_header.pcap> pcap, int netmask) {
    super(pcap, netmask);
  }

  @Override
  public Handle event() {
    return new HandleImpl(WinPcapMapping.MAPPING.pcap_getevent(pcap));
  }

  public static class HandleImpl implements Handle {

    public final Pointer<Void> ptr;

    private HandleImpl(Pointer<Void> ptr) {
      this.ptr = ptr;
    }

    @Override
    public long address() {
      return ptr.addr();
    }
  }
}
