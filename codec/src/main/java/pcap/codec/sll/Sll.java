/*
 * Copyright (c) 2020-2021 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.codec.sll;

import java.util.Arrays;
import java.util.Objects;
import pcap.codec.AbstractPacket;
import pcap.codec.ethernet.Ethernet;
import pcap.common.util.Strings;
import pcap.common.util.Validate;
import pcap.spi.PacketBuffer;

/**
 * Linux cooked packet (SLL).
 *
 * @since 1.3.0
 */
public final class Sll extends AbstractPacket {

  public static final int TYPE = 113;

  private static final int SLL_ADDRLEN = 8;

  // offsets
  private final long packetTypeOffset;
  private final long addressTypeOffset;
  private final long addressLengthOffset;
  private final long addressOffset;
  private final long protocolOffset;

  private Sll(PacketBuffer buffer) {
    super(buffer);
    packetTypeOffset = superOffset;
    addressTypeOffset = packetTypeOffset + 2;
    addressLengthOffset = addressTypeOffset + 2;
    addressOffset = addressLengthOffset + 2;
    protocolOffset = addressOffset + SLL_ADDRLEN;
  }

  /**
   * Wrap buffer into {@link Ethernet}.
   *
   * @param size ethernet size.
   * @param buffer buffer.
   * @return returns {@link Ethernet} instance.
   * @since 1.3.0
   */
  public static Sll newInstance(int size, PacketBuffer buffer) {
    Validate.notIllegalArgument(
        size == 16 && buffer.readableBytes() >= 16, "buffer size is not sufficient.");
    return new Sll(buffer);
  }

  /**
   * Get packet type.
   *
   * @return returns this instance.
   * @since 1.3.0
   */
  public int packetType() {
    return superBuffer.getShort(packetTypeOffset);
  }

  /**
   * Set packet type.
   *
   * @param value packet type.
   * @return returns this instance.
   * @since 1.3.0
   */
  public Sll packetType(int value) {
    superBuffer.setShort(packetTypeOffset, value & 0xFFFF);
    return this;
  }

  /**
   * Get link layer address type.
   *
   * @return returns link layer address type.
   * @since 1.3.0
   */
  public int addressType() {
    return superBuffer.getShort(addressTypeOffset);
  }

  /**
   * Set link layer address type.
   *
   * @param value link layer address type.
   * @return returns this instance.
   * @since 1.3.0
   */
  public Sll addressType(int value) {
    superBuffer.setShort(addressTypeOffset, value & 0xFFFF);
    return this;
  }

  /**
   * Get link layer address length.
   *
   * @return returns link layer address length.
   * @since 1.3.0
   */
  public int addressLength() {
    return superBuffer.getShort(addressLengthOffset);
  }

  /**
   * Set link layer address length.
   *
   * @param value link layer address length.
   * @return returns this instance.
   * @since 1.3.0
   */
  public Sll addressLength(int value) {
    superBuffer.setShort(addressLengthOffset, value & 0xFFFF);
    return this;
  }

  /**
   * Get link layer address.
   *
   * @return returns link layer address.
   * @since 1.3.0
   */
  public byte[] address() {
    int addrLen = addressLength();
    if (addrLen > 0 && addrLen <= SLL_ADDRLEN) {
      byte[] addr = new byte[addrLen];
      superBuffer.getBytes(addressOffset, addr);
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
   * @since 1.3.0
   */
  public Sll address(byte[] value) {
    int addrLen = addressLength();
    if (addrLen > 0 && addrLen <= SLL_ADDRLEN) {
      if (value == null) {
        superBuffer.setBytes(addrLen, new byte[addrLen], 0, addrLen);
      } else {
        superBuffer.setBytes(addressOffset, value, 0, addrLen);
      }
    } else {
      throw new IllegalArgumentException(
          String.format(
              "addressLength: %d (expected: addressLength(%d) > 0 and addressLength(%d) <= 8)",
              addrLen, addrLen, addrLen));
    }
    return this;
  }

  /**
   * Get next protocol type.
   *
   * @return returns protocol.
   * @since 1.3.0
   */
  public int protocol() {
    return superBuffer.getShort(protocolOffset);
  }

  /**
   * Set next protocol type.
   *
   * @param value protocol.
   * @return returns this instance.
   * @since 1.3.0
   */
  public Sll protocol(int value) {
    superBuffer.setShort(protocolOffset, value & 0xFFFF);
    return this;
  }

  /** {@inheritDoc} */
  @Override
  public int size() {
    return 16;
  }

  @Override
  public boolean equals(Object o) {
    return super.equals(o);
  }

  @Override
  public int hashCode() {
    return Objects.hash(
        super.hashCode(),
        packetType(),
        addressType(),
        addressLength(),
        Arrays.hashCode(address()),
        protocol());
  }

  @Override
  public String toString() {
    return Strings.toStringBuilder(this)
        .add("packetType", packetType())
        .add("addressType", addressType())
        .add("addressLength", addressLength())
        .add("address", String.format("0x%s", Strings.hex(address())))
        .add("protocol", protocol())
        .toString();
  }
}
