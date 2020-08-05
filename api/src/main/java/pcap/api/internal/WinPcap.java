/** This code is licenced under the GPL version 2. */
package pcap.api.internal;

import java.foreign.memory.Pointer;
import pcap.api.internal.foreign.pcap_header;

/**
 * Windows {@code Pcap} handle.
 *
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 */
public class WinPcap extends Pcap {

  public WinPcap(Pointer<pcap_header.pcap> pcap) {
    super(pcap);
  }

  public WinPcap(Pointer<pcap_header.pcap> pcap, int netmask) {
    super(pcap, netmask);
  }
}
