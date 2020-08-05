/** This code is licenced under the GPL version 2. */
package pcap.api.internal;

import java.foreign.memory.Pointer;
import pcap.api.internal.foreign.mapping.UnixPcapMapping;
import pcap.api.internal.foreign.pcap_header;
import pcap.spi.Timestamp;

/**
 * Unix {@code Pcap} handle.
 *
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 */
public class UnixPcap extends Pcap implements pcap.spi.Pcap.UnixPcap {

  public UnixPcap(Pointer<pcap_header.pcap> pcap) {
    super(pcap);
  }

  public UnixPcap(Pointer<pcap_header.pcap> pcap, int netmask) {
    super(pcap, netmask);
  }

  @Override
  public int selectableFd() {
    return UnixPcapMapping.MAPPING.pcap_get_selectable_fd(pcap);
  }

  @Override
  public Timestamp requiredSelectTimeout() {
    return UnixPcapMapping.MAPPING.pcap_get_required_select_timeout(pcap).get().timestamp();
  }
}
