/*
 * Copyright (c) 2020-2023 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.codec.udp;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.util.Objects;
import pcap.codec.AbstractPacket;
import pcap.common.util.Strings;
import pcap.common.util.Validate;
import pcap.spi.PacketBuffer;

/**
 * UDP
 *
 * @since 1.0.0
 */
public final class Udp extends AbstractPacket {

  public static final int TYPE = 17;

  // Header fields offset.
  private final long sourcePortOffset;
  private final long destinationPortOffset;
  private final long lengthOffset;
  private final long checksumOffset;

  private Udp(PacketBuffer buffer) {
    super(buffer);
    this.sourcePortOffset = superOffset;
    this.destinationPortOffset = sourcePortOffset + 2;
    this.lengthOffset = destinationPortOffset + 2;
    this.checksumOffset = lengthOffset + 2;
  }

  /**
   * Wrap buffer into {@link Udp}.
   *
   * @param size {@link Udp} header size.
   * @param buffer buffer.
   * @return returns {@link Udp} instance.
   * @since 1.0.0
   */
  public static Udp newInstance(int size, PacketBuffer buffer) {
    Validate.notIllegalArgument(
        size >= 8 && size <= 65535 && buffer.readableBytes() >= 8,
        "buffer size is not sufficient.");
    return new Udp(buffer);
  }

  /**
   * Get source port.
   *
   * @return returns source port.
   * @since 1.0.0
   */
  public int sourcePort() {
    return superBuffer.getShort(sourcePortOffset) & 0xFFFF;
  }

  /**
   * Set source port.
   *
   * @param value source port.
   * @return returns this instance.
   * @since 1.0.0
   */
  public Udp sourcePort(int value) {
    superBuffer.setShort(sourcePortOffset, value & 0xFFFF);
    return this;
  }

  /**
   * Get destination port.
   *
   * @return returns destination port.
   * @since 1.0.0
   */
  public int destinationPort() {
    return superBuffer.getShort(destinationPortOffset) & 0xFFFF;
  }

  /**
   * Set destination port.
   *
   * @param value destination port.
   * @return returns this instance.
   * @since 1.0.0
   */
  public Udp destinationPort(int value) {
    superBuffer.setShort(destinationPortOffset, value & 0xFFFF);
    return this;
  }

  /**
   * Get length.
   *
   * @return returns length.
   * @since 1.0.0
   */
  public int length() {
    return superBuffer.getShort(lengthOffset) & 0xFFFF;
  }

  /**
   * Set length,
   *
   * @param value length.
   * @return returns this instance.
   * @since 1.0.0
   */
  public Udp length(int value) {
    superBuffer.setShort(lengthOffset, value & 0xFFFF);
    return this;
  }

  /**
   * Get checksum.
   *
   * @return returns checksum.
   * @since 1.0.0
   */
  public int checksum() {
    return superBuffer.getShort(checksumOffset) & 0xFFFF;
  }

  /**
   * Set checksum, calculate checksum with {@link Udp#calculateChecksum(InetAddress, InetAddress)}.
   *
   * @param value checksum.
   * @return returns this instance.
   * @since 1.0.0
   */
  public Udp checksum(int value) {
    superBuffer.setShort(checksumOffset, value & 0xFFFF);
    return this;
  }

  /**
   * Calculate this header checksum.
   *
   * @param srcAddr source IP address.
   * @param dstAddr destination IP address.
   * @return returns checksum.
   * @since 1.0.0
   */
  public int calculateChecksum(InetAddress srcAddr, InetAddress dstAddr) {
    return Checksum.calculate(
        superBuffer, superOffset, srcAddr, dstAddr, TYPE, size(), length() - size());
  }

  /**
   * Check if this header has valid checksum value.
   *
   * @param src source IP address.
   * @param dst destination IP address.
   * @return returns {@code true} if valid, {@code false} otherwis.
   * @since 1.0.0
   */
  public boolean isValidChecksum(Inet4Address src, Inet4Address dst) {
    return calculateChecksum(src, dst) == 0;
  }

  /** {@inheritDoc} */
  @Override
  public int size() {
    return 8;
  }

  @Override
  public boolean equals(Object o) {
    return super.equals(o);
  }

  @Override
  public int hashCode() {
    return Objects.hash(super.hashCode(), sourcePort(), destinationPort(), length(), checksum());
  }

  @Override
  public String toString() {
    return Strings.toStringBuilder(this)
        .add("sourcePort", sourcePort())
        .add("destinationPort", destinationPort())
        .add("length", length())
        .add("checksum", String.format("0x%s", Integer.toHexString(checksum())))
        .toString();
  }
}
