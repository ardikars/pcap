/** This code is licenced under the GPL version 2. */
package pcap.api.internal;

import java.foreign.memory.Pointer;
import pcap.api.internal.foreign.mapping.PcapMapping;
import pcap.api.internal.foreign.mapping.WindowsPcapMapping;
import pcap.api.internal.foreign.pcap_header;
import pcap.common.annotation.Inclubating;
import pcap.spi.PacketBuffer;
import pcap.spi.PacketHeader;

/**
 * Windows {@code Pcap} dumper handle.
 *
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 */
@Inclubating
public class WindowsPcapDumper extends PcapDumper {

  public WindowsPcapDumper(Pointer<pcap_header.pcap_dumper> pcap_dumper) {
    super(pcap_dumper);
  }

  @Override
  public void dump(PacketHeader header, PacketBuffer buffer) {
    synchronized (PcapMapping.LOCK) {
      WindowsPcapMapping.MAPPING.pcap_dump(
          reference, ((WindowsPacketHeader) header).ref, ((PcapPacketBuffer) buffer).ref);
    }
  }
}
