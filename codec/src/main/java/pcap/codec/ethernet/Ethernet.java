/*
 * Copyright (c) 2020-2021 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.codec.ethernet;

import java.util.Objects;
import pcap.codec.AbstractPacket;
import pcap.common.net.MacAddress;
import pcap.common.util.Strings;
import pcap.common.util.Validate;
import pcap.spi.PacketBuffer;

/**
 * Ethernet header.
 *
 * @since 1.0.0
 */
public final class Ethernet extends AbstractPacket {

  public static final int TYPE = 1;

  // Header fields offset.
  private final long destinationOffset;
  private final long sourceOffset;
  private final long typeOffset;

  private Ethernet(PacketBuffer buffer) {
    super(buffer);
    this.destinationOffset = superOffset;
    this.sourceOffset = destinationOffset + MacAddress.MAC_ADDRESS_LENGTH;
    this.typeOffset = sourceOffset + MacAddress.MAC_ADDRESS_LENGTH;
  }

  /**
   * Wrap buffer into {@link Ethernet}.
   *
   * @param size ethernet size.
   * @param buffer buffer.
   * @return returns {@link Ethernet} instance.
   * @since 1.0.0
   */
  public static Ethernet newInstance(int size, PacketBuffer buffer) {
    Validate.notIllegalArgument(
        size == 14 && buffer.readableBytes() >= 14, "buffer size is not sufficient.");
    return new Ethernet(buffer);
  }

  /**
   * Get destination hardware address ({@link MacAddress}.
   *
   * @return returns {@link MacAddress}.
   * @since 1.0.0
   */
  public MacAddress destination() {
    return MacAddress.valueOf((superBuffer.getLong(destinationOffset) >> 16) & 0xffffffffffffL);
  }

  /**
   * Set destination hardware address ({@link MacAddress}).
   *
   * @param macAddress mac address.
   * @return returns this instance.
   * @since 1.0.0
   */
  public Ethernet destination(MacAddress macAddress) {
    superBuffer.setBytes(destinationOffset, macAddress.address());
    return this;
  }

  /**
   * Get source hardware address ({@link MacAddress}).
   *
   * @return returns {@link MacAddress}.
   * @since 1.0.0
   */
  public MacAddress source() {
    return MacAddress.valueOf((superBuffer.getLong(sourceOffset) >> 16) & 0xffffffffffffL);
  }

  /**
   * Set source hardware address ({@link MacAddress}).
   *
   * @param macAddress mac address.
   * @return returns this instance.
   * @since 1.0.0
   */
  public Ethernet source(MacAddress macAddress) {
    superBuffer.setBytes(sourceOffset, macAddress.address());
    return this;
  }

  /**
   * Get ethernet type.
   *
   * @return returns ethernet type.
   * @since 1.0.0
   */
  public int type() {
    return superBuffer.getShort(typeOffset) & 0xFFFF;
  }

  /**
   * Set ethernet type.
   *
   * @param value ethernet type.
   * @return returns this instance.
   * @since 1.0.0
   */
  public Ethernet type(int value) {
    superBuffer.setShort(typeOffset, value & 0xFFFF);
    return this;
  }

  /** {@inheritDoc} */
  @Override
  public int size() {
    return 14;
  }

  @Override
  public boolean equals(Object o) {
    return super.equals(o);
  }

  @Override
  public int hashCode() {
    return Objects.hash(super.hashCode(), destination(), source(), type());
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
