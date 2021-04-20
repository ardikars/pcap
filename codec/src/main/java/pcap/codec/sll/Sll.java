package pcap.codec.sll;

import pcap.codec.AbstractPacket;
import pcap.codec.ethernet.Ethernet;
import pcap.common.util.Strings;
import pcap.common.util.Validate;
import pcap.spi.PacketBuffer;
import pcap.spi.annotation.Incubating;

/**
 * Linux cooked packet (SLL).
 *
 * @since 1.3.0 (incubating)
 */
@Incubating
public class Sll extends AbstractPacket {

  private static final int SLL_ADDRLEN = 8;

  // offsets
  private final long packetType;
  private final long addressType;
  private final long addressLength;
  private final long address;
  private final long protocol;

  private Sll(PacketBuffer buffer) {
    super(buffer);
    packetType = offset;
    addressType = packetType + 2;
    addressLength = addressType + 2;
    address = addressLength + 2;
    protocol = address + SLL_ADDRLEN;
  }

  /**
   * Wrap buffer into {@link Ethernet}.
   *
   * @param size ethernet size.
   * @param buffer buffer.
   * @return returns {@link Ethernet} instance.
   * @since 1.3.0 (incubating)
   */
  @Incubating
  public static Sll newInstance(int size, PacketBuffer buffer) {
    Validate.notIllegalArgument(
        size == 16 && buffer.readableBytes() >= 16, "buffer size is not sufficient.");
    return new Sll(buffer);
  }

  /**
   * Get packet type.
   *
   * @return returns this instance.
   * @since 1.3.0 (incubating)
   */
  @Incubating
  public int packetType() {
    return buffer.getShort(packetType);
  }

  /**
   * Set packet type.
   *
   * @param value packet type.
   * @return returns this instance.
   * @since 1.3.0 (incubating)
   */
  @Incubating
  public Sll packetType(int value) {
    buffer.setShort(packetType, value & 0xFFFF);
    return this;
  }

  /**
   * Get link layer address type.
   *
   * @return returns link layer address type.
   * @since 1.3.0 (incubating)
   */
  @Incubating
  public int addressType() {
    return buffer.getShort(addressType);
  }

  /**
   * Set link layer address type.
   *
   * @param value link layer address type.
   * @return returns this instance.
   * @since 1.3.0 (incubating)
   */
  @Incubating
  public Sll addressType(int value) {
    buffer.setShort(addressType, value & 0xFFFF);
    return this;
  }

  /**
   * Get link layer address length.
   *
   * @return returns link layer address length.
   * @since 1.3.0 (incubating)
   */
  @Incubating
  public int addressLength() {
    return buffer.getShort(addressLength);
  }

  /**
   * Set link layer address length.
   *
   * @param value link layer address length.
   * @return returns this instance.
   * @since 1.3.0 (incubating)
   */
  @Incubating
  public Sll addressLength(int value) {
    buffer.setShort(addressLength, value & 0xFFFF);
    return this;
  }

  /**
   * Get link layer address.
   *
   * @return returns link layer address.
   * @since 1.3.0 (incubating)
   */
  @Incubating
  public byte[] address() {
    int addrLen = addressLength();
    if (addrLen > 0) {
      byte[] addr = new byte[addrLen];
      buffer.getBytes(address, addr);
      return addr;
    } else {
      return new byte[SLL_ADDRLEN];
    }
  }

  /**
   * Set link layer address.
   *
   * @param value link layer address.
   * @return returns this instance.
   * @since 1.3.0 (incubating)
   */
  @Incubating
  public Sll address(byte[] value) {
    int addrLen = addressLength();
    if (addrLen > 0) {
      buffer.setBytes(address, value, 0, addrLen);
    }
    return this;
  }

  /**
   * Get next protocol type.
   *
   * @return returns protocol.
   * @since 1.3.0 (incubating)
   */
  @Incubating
  public int protocol() {
    return buffer.getShort(protocol);
  }

  /**
   * Set next protocol type.
   *
   * @param value protocol.
   * @return returns this instance.
   * @since 1.3.0 (incubating)
   */
  @Incubating
  public Sll protocol(int value) {
    buffer.setShort(protocol, value & 0xFFFF);
    return this;
  }

  /** {@inheritDoc} */
  @Override
  public int size() {
    return 16;
  }

  @Override
  public String toString() {
    return Strings.toStringBuilder(this)
        .add("packetType", packetType())
        .add("addressType", addressType())
        .add("addressLength", addressLength())
        .add("address", "0x" + Strings.hex(address()))
        .add("protocol", protocol())
        .toString();
  }
}
