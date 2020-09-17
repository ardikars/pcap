package pcap.api.jdk7;

import com.sun.jna.Pointer;
import pcap.spi.Dumper;
import pcap.spi.PacketBuffer;
import pcap.spi.PacketHeader;

public class DefaultDumper implements Dumper {

  private final Pointer pointer;

  public DefaultDumper(Pointer pointer) {
    this.pointer = pointer;
  }

  @Override
  public void dump(PacketHeader header, PacketBuffer buffer) {
    DefaultPacketHeader packetHeader = (DefaultPacketHeader) header;
    DefaultPacketBuffer packetBuffer = (DefaultPacketBuffer) buffer;
    NativeMappings.pcap_dump(pointer, packetHeader, packetBuffer);
  }

  @Override
  public long position() {
    return NativeMappings.pcap_dump_ftell(pointer).longValue();
  }

  @Override
  public void flush() {
    NativeMappings.pcap_dump_flush(pointer);
  }

  @Override
  public void close() {
    NativeMappings.pcap_dump_close(pointer);
  }
}
