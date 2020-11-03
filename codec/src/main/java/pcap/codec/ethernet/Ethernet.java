package pcap.codec.ethernet;

import pcap.common.net.MacAddress;
import pcap.common.util.Strings;
import pcap.spi.Packet;
import pcap.spi.PacketBuffer;
import pcap.spi.annotation.Incubating;

@Incubating
public class Ethernet extends Packet.Abstract {

  public static final int TYPE = 1;

  private final long destination;
  private final long source;
  private final long type;

  public Ethernet(PacketBuffer buffer) {
    super(buffer);
    this.destination = offset;
    this.source = destination + MacAddress.MAC_ADDRESS_LENGTH;
    this.type = source + MacAddress.MAC_ADDRESS_LENGTH;
  }

  public MacAddress destination() {
    return getMacAddress(destination);
  }

  public Ethernet destination(MacAddress macAddress) {
    buffer.setBytes(destination, macAddress.address());
    return this;
  }

  public MacAddress source() {
    return getMacAddress(source);
  }

  public Ethernet source(MacAddress macAddress) {
    buffer.setBytes(source, macAddress.address());
    return this;
  }

  public int type() {
    return buffer.getShortRE(type);
  }

  public Ethernet type(int value) {
    buffer.setShortRE(type, value);
    return this;
  }

  @Override
  public int size() {
    return 14;
  }

  private MacAddress getMacAddress(long offset) {
    byte[] macAddress = new byte[MacAddress.MAC_ADDRESS_LENGTH];
    buffer.getBytes(offset, macAddress);
    return MacAddress.valueOf(macAddress);
  }

  @Override
  public String toString() {
    return Strings.toStringBuilder(this)
        .add("destination", destination())
        .add("source", source())
        .add("type", type())
        .toString();
  }
}
