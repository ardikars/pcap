/** This code is licenced under the GPL version 2. */
package pcap.api.internal;

import java.foreign.NativeTypes;
import java.foreign.memory.Pointer;
import pcap.api.internal.foreign.mapping.PcapMapping;
import pcap.api.internal.foreign.pcap_header;
import pcap.common.annotation.Inclubating;
import pcap.spi.Dumper;
import pcap.spi.PacketBuffer;
import pcap.spi.PacketHeader;

/**
 * {@code Pcap} dumper implementation.
 *
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 */
@Inclubating
public class PcapDumper implements Dumper {

  final Pointer<pcap_header.pcap_dumper> pcap_dumper;
  final Pointer<Byte> reference;

  public PcapDumper(Pointer<pcap_header.pcap_dumper> pcap_dumper) {
    this.pcap_dumper = pcap_dumper;
    this.reference = pcap_dumper.cast(NativeTypes.VOID).cast(NativeTypes.UINT8);
  }

  @Override
  public void dump(PacketHeader header, PacketBuffer buffer) {
    synchronized (PcapMapping.LOCK) {
      PcapMapping.MAPPING.pcap_dump(
          reference, ((PcapPacketHeader.Impl) header).ref, ((PcapPacketBuffer) buffer).ref);
    }
  }

  @Override
  public long position() {
    synchronized (PcapMapping.LOCK) {
      return PcapMapping.MAPPING.pcap_dump_ftell(pcap_dumper);
    }
  }

  @Override
  public void flush() {
    synchronized (PcapMapping.LOCK) {
      PcapMapping.MAPPING.pcap_dump_flush(pcap_dumper);
    }
  }

  @Override
  public void close() {
    synchronized (PcapMapping.LOCK) {
      if (!pcap_dumper.isNull()) {
        PcapMapping.MAPPING.pcap_dump_close(pcap_dumper);
      }
    }
  }
}
