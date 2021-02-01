package pcap.codec.ip.extension;

import pcap.spi.Packet;
import pcap.spi.PacketBuffer;
import pcap.spi.annotation.Incubating;

@Incubating
public final class EncapsulatingSecurityProtocol extends Packet.Abstract {

  private EncapsulatingSecurityProtocol(PacketBuffer buffer) {
    super(buffer);
  }

  @Override
  public int size() {
    return 0;
  }
}
