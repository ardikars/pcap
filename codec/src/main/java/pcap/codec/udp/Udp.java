/*
 * Copyright (c) 2020 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.codec.udp;

import java.net.Inet4Address;
import java.net.InetAddress;
import pcap.codec.AbstractPacket;
import pcap.common.util.Strings;
import pcap.common.util.Validate;
import pcap.spi.PacketBuffer;
import pcap.spi.annotation.Incubating;

/**
 * UDP
 *
 * @since 1.0.0 (incubating)
 */
@Incubating
public final class Udp extends AbstractPacket {

  public static final int TYPE = 17;

  // Header fields offset.
  private final long sourcePort;
  private final long destinationPort;
  private final long length;
  private final long checksum;

  private Udp(PacketBuffer buffer) {
    super(buffer);
    this.sourcePort = offset;
    this.destinationPort = sourcePort + 2;
    this.length = destinationPort + 2;
    this.checksum = length + 2;
  }

  /**
   * Wrap buffer into {@link Udp}.
   *
   * @param size {@link Udp} header size.
   * @param buffer buffer.
   * @return returns {@link Udp} instance.
   * @since 1.0.0 (incubating)
   */
  @Incubating
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
   * @since 1.0.0 (incubating)
   */
  @Incubating
  public int sourcePort() {
    return buffer.getShort(sourcePort) & 0xFFFF;
  }

  /**
   * Set source port.
   *
   * @param value source port.
   * @return returns this instance.
   * @since 1.0.0 (incubating)
   */
  @Incubating
  public Udp sourcePort(int value) {
    buffer.setShort(sourcePort, value & 0xFFFF);
    return this;
  }

  /**
   * Get destination port.
   *
   * @return returns destination port.
   * @since 1.0.0 (incubating)
   */
  @Incubating
  public int destinationPort() {
    return buffer.getShort(destinationPort) & 0xFFFF;
  }

  /**
   * Set destination port.
   *
   * @param value destination port.
   * @return returns this instance.
   * @since 1.0.0 (incubating)
   */
  @Incubating
  public Udp destinationPort(int value) {
    buffer.setShort(destinationPort, value & 0xFFFF);
    return this;
  }

  /**
   * Get length.
   *
   * @return returns length.
   * @since 1.0.0 (incubating)
   */
  @Incubating
  public int length() {
    return buffer.getShort(length) & 0xFFFF;
  }

  /**
   * Set length,
   *
   * @param value length.
   * @return returns this instance.
   * @since 1.0.0 (incubating)
   */
  @Incubating
  public Udp length(int value) {
    buffer.setShort(length, value & 0xFFFF);
    return this;
  }

  /**
   * Get checksum.
   *
   * @return returns checksum.
   * @since 1.0.0 (incubating)
   */
  @Incubating
  public int checksum() {
    return buffer.getShort(checksum) & 0xFFFF;
  }

  /**
   * Set checksum, calculate checksum with {@link Udp#calculateChecksum(InetAddress, InetAddress)}.
   *
   * @param value checksum.
   * @return returns this instance.
   * @since 1.0.0 (incubating)
   */
  @Incubating
  public Udp checksum(int value) {
    buffer.setShort(checksum, value & 0xFFFF);
    return this;
  }

  /**
   * Calculate this header checksum.
   *
   * @param srcAddr source IP address.
   * @param dstAddr destination IP address.
   * @return returns checksum.
   * @since 1.0.0 (incubating)
   */
  @Incubating
  public int calculateChecksum(InetAddress srcAddr, InetAddress dstAddr) {
    return Checksum.calculate(buffer, offset, srcAddr, dstAddr, TYPE, size(), length() - size());
  }

  /**
   * Check if this header has valid checksum value.
   *
   * @param src source IP address.
   * @param dst destination IP address.
   * @return returns {@code true} if valid, {@code false} otherwis.
   * @since 1.0.0 (incubating)
   */
  @Incubating
  public boolean isValidChecksum(Inet4Address src, Inet4Address dst) {
    return calculateChecksum(src, dst) == 0;
  }

  /** {@inheritDoc} */
  @Override
  public int size() {
    return 8;
  }

  @Override
  public String toString() {
    return Strings.toStringBuilder(this)
        .add("sourcePort", sourcePort())
        .add("destinationPort", destinationPort())
        .add("length", length())
        .add("checksum", "0x" + Integer.toHexString(checksum()))
        .toString();
  }
}
