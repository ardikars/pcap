/*
 * Copyright (c) 2020 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.codec.ethernet;

import pcap.codec.AbstractPacket;
import pcap.common.net.MacAddress;
import pcap.common.util.Strings;
import pcap.common.util.Validate;
import pcap.spi.PacketBuffer;
import pcap.spi.annotation.Incubating;

/**
 * Ethernet header.
 *
 * @since 1.0.0 (incubating)
 */
@Incubating
public final class Ethernet extends AbstractPacket {

  public static final int TYPE = 1;

  // Header fields offset.
  private final long destination;
  private final long source;
  private final long type;

  private Ethernet(PacketBuffer buffer) {
    super(buffer);
    this.destination = offset;
    this.source = destination + MacAddress.MAC_ADDRESS_LENGTH;
    this.type = source + MacAddress.MAC_ADDRESS_LENGTH;
  }

  /**
   * Wrap buffer into {@link Ethernet}.
   *
   * @param size ethernet size.
   * @param buffer buffer.
   * @return returns {@link Ethernet} instance.
   * @since 1.0.0 (incubating)
   */
  @Incubating
  public static Ethernet newInstance(int size, PacketBuffer buffer) {
    Validate.notIllegalArgument(
        size == 14 && buffer.readableBytes() >= 14, "buffer size is not sufficient.");
    return new Ethernet(buffer);
  }

  /**
   * Get destination hardware address ({@link MacAddress}.
   *
   * @return returns {@link MacAddress}.
   * @since 1.0.0 (incubating)
   */
  @Incubating
  public MacAddress destination() {
    return MacAddress.valueOf((buffer.getLong(destination) >> 16) & 0xffffffffffffL);
  }

  /**
   * Set destination hardware address ({@link MacAddress}).
   *
   * @param macAddress mac address.
   * @return returns this instance.
   * @since 1.0.0 (incubating)
   */
  @Incubating
  public Ethernet destination(MacAddress macAddress) {
    buffer.setBytes(destination, macAddress.address());
    return this;
  }

  /**
   * Get source hardware address ({@link MacAddress}).
   *
   * @return returns {@link MacAddress}.
   * @since 1.0.0 (incubating)
   */
  @Incubating
  public MacAddress source() {
    return MacAddress.valueOf((buffer.getLong(source) >> 16) & 0xffffffffffffL);
  }

  /**
   * Set source hardware address ({@link MacAddress}).
   *
   * @param macAddress mac address.
   * @return returns this instance.
   * @since 1.0.0 (incubating)
   */
  @Incubating
  public Ethernet source(MacAddress macAddress) {
    buffer.setBytes(source, macAddress.address());
    return this;
  }

  /**
   * Get ethernet type.
   *
   * @return returns ethernet type.
   * @since 1.0.0 (incubating)
   */
  @Incubating
  public int type() {
    return buffer.getShort(type) & 0xFFFF;
  }

  /**
   * Set ethernet type.
   *
   * @param value ethernet type.
   * @return returns this instance.
   * @since 1.0.0 (incubating)
   */
  @Incubating
  public Ethernet type(int value) {
    buffer.setShort(type, value & 0xFFFF);
    return this;
  }

  /** {@inheritDoc} */
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
