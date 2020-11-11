package pcap.codec.ethernet;

import pcap.codec.AbstractPacket;
import pcap.common.net.MacAddress;
import pcap.common.util.Strings;
import pcap.common.util.Validate;
import pcap.spi.PacketBuffer;
import pcap.spi.annotation.Incubating;

/**
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 * @since 1.0.0
 */
@Incubating
public final class Ethernet extends AbstractPacket {

  public static final int TYPE = 1;

  private final long destination;
  private final long source;
  private final long type;

  private Ethernet(PacketBuffer buffer) {
    super(buffer);
    this.destination = offset;
    this.source = destination + MacAddress.MAC_ADDRESS_LENGTH;
    this.type = source + MacAddress.MAC_ADDRESS_LENGTH;
  }

  public static Ethernet newInstance(int size, PacketBuffer buffer) {
    Validate.notIllegalArgument(
        size == 14 && buffer.readableBytes() >= 14, "buffer size is not sufficient.");
    return new Ethernet(buffer);
  }

  public MacAddress destination() {
    return MacAddress.valueOf((buffer.getLong(destination) >> 16) & 0xffffffffffffL);
  }

  public Ethernet destination(MacAddress macAddress) {
    buffer.setBytes(destination, macAddress.address());
    return this;
  }

  public MacAddress source() {
    return MacAddress.valueOf((buffer.getLong(source) >> 16) & 0xffffffffffffL);
  }

  public Ethernet source(MacAddress macAddress) {
    buffer.setBytes(source, macAddress.address());
    return this;
  }

  public int type() {
    return buffer.getShort(type) & 0xFFFF;
  }

  public Ethernet type(int value) {
    buffer.setShort(type, value & 0xFFFF);
    return this;
  }

  @Override
  public int size() {
    return 14;
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
