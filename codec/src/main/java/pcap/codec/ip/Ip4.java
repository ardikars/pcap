/*
 * Copyright (c) 2020-2021 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.codec.ip;

import pcap.codec.AbstractPacket;
import pcap.common.net.InetAddresses;
import pcap.common.util.Bytes;
import pcap.common.util.Strings;
import pcap.common.util.Validate;
import pcap.spi.PacketBuffer;

import java.net.Inet4Address;

/*
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |Version|  IHL  |Type of Service|          Total Length         |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |         Identification        |Flags|      Fragment Offset    |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |  Time to Live |    Protocol   |         Header Checksum       |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                       Source Address                          |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                    Destination Address                        |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                    Options                    |    Padding    |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
/**
 * IPv4
 *
 * <ul>
 *   <li>https://tools.ietf.org/html/rfc791
 *   <li>https://tools.ietf.org/html/rfc3168
 * </ul>
 *
 * @since 1.0.0
 */
public final class Ip4 extends AbstractPacket {

  public static final int TYPE = 0x0800;

  // Header fields offset.
  private final long version;
  private final long dscp;
  private final long totalLength;
  private final long identification;
  private final long flags;
  private final long ttl;
  private final long protocol;
  private final long headerChecksum;
  private final long source;
  private final long destination;
  private final long options;

  private final int maxIhl;

  private Ip4(PacketBuffer buffer) {
    super(buffer);
    this.version = offset;
    this.dscp = version + 1;
    this.totalLength = dscp + 1;
    this.identification = totalLength + 2;
    this.flags = identification + 2;
    this.ttl = flags + 2;
    this.protocol = ttl + 1;
    this.headerChecksum = protocol + 1;
    this.source = headerChecksum + 2;
    this.destination = source + 4;
    this.options = destination + 4;
    this.maxIhl = ihl();
  }

  /**
   * Wrap buffer into {@link Ip4}.
   *
   * @param size {@link Ip4} header size.
   * @param buffer buffer.
   * @return returns {@link Ip4} instance.
   * @since 1.0.0
   */
  public static Ip4 newInstance(int size, PacketBuffer buffer) {
    Validate.notIllegalArgument(
        size >= 20 && size <= 60 && buffer.readableBytes() >= 20, "buffer size is not sufficient.");
    buffer.setByte(buffer.readerIndex(), (4 & 0xF) << 4 | (size >> 2) & 0xF);
    return new Ip4(buffer);
  }

  /**
   * Get IP version number (4).
   *
   * @return returns IP version number (4).
   * @since 1.0.0
   */
  public int version() {
    return (buffer.getByte(version) >> 4) & 0xF;
  }

  /**
   * Set IP version number (4).
   *
   * @param value version number (4).
   * @return returns this instance.
   * @since 1.0.0
   */
  public Ip4 version(int value) {
    buffer.setByte(version, (value & 0xF) << 4 | ihl());
    return this;
  }

  /**
   * Get IHL.
   *
   * @return returns IHL.
   * @since 1.0.0
   */
  public int ihl() {
    return buffer.getByte(version) & 0xF;
  }

  /**
   * Set IHL.
   *
   * @param value IHL.
   * @return returns this instance.
   * @since 1.0.0
   */
  public Ip4 ihl(int value) {
    if (value < 5 || value > maxIhl) {
      throw new IllegalArgumentException(
          String.format("value: %d (expected: 5 >= value <= %d)", value, maxIhl));
    }
    buffer.setByte(version, version() << 4 | value & 0xF);
    return this;
  }

  /**
   * Get DSCP.
   *
   * @return returns DSCP.
   * @since 1.0.0
   */
  public int dscp() {
    return (buffer.getByte(dscp) >> 2) & 0x3F;
  }

  /**
   * Set DSCP.
   *
   * @param value DSCP.
   * @return returns this instance.
   * @since 1.0.0
   */
  public Ip4 dscp(int value) {
    buffer.setByte(dscp, (value & 0x3F) << 2 | ecn());
    return this;
  }

  /**
   * Get ECN.
   *
   * @return returns ECN.
   * @since 1.0.0
   */
  public int ecn() {
    return buffer.getByte(dscp) & 0x3;
  }

  /**
   * Set ECN.
   *
   * @param value ECN.
   * @return returns this instance.
   * @since 1.0.0
   */
  public Ip4 ecn(int value) {
    buffer.setByte(dscp, dscp() << 2 | value & 0x3);
    return this;
  }

  /**
   * Get total length.
   *
   * @return returns total length.
   * @since 1.0.0
   */
  public int totalLength() {
    return buffer.getShort(totalLength) & 0xFFFF;
  }

  /**
   * Set total length.
   *
   * @param value total length.
   * @return returns this instance.
   * @since 1.0.0
   */
  public Ip4 totalLength(int value) {
    buffer.setShort(totalLength, value & 0xFFFF);
    return this;
  }

  /**
   * Get identification.
   *
   * @return returns identification.
   * @since 1.0.0
   */
  public int identification() {
    return buffer.getShort(identification) & 0xFFFF;
  }

  /**
   * Set identification.
   *
   * @param value identification.
   * @return returns this instance.
   * @since 1.0.0
   */
  public Ip4 identification(int value) {
    buffer.setShort(identification, value & 0xFFFF);
    return this;
  }

  /**
   * Get flags.
   *
   * @return returns flags.
   * @since 1.0.0
   */
  public int flags() {
    return (buffer.getShort(flags) >> 13) & 0x7;
  }

  /**
   * Set flags.
   *
   * @param value flags.
   * @return this instance.
   * @since 1.0.0
   */
  public Ip4 flags(int value) {
    buffer.setShort(flags, (value & 0x7) << 13 | fragmentOffset());
    return this;
  }

  /**
   * Get fragment offset.
   *
   * @return returns fragment offset.
   * @since 1.0.0
   */
  public int fragmentOffset() {
    return buffer.getShort(flags) & 0x1FFF;
  }

  /**
   * Set fragment offset.
   *
   * @param value fragment offset.
   * @return returns this instance.
   * @since 1.0.0
   */
  public Ip4 fragmentOffset(int value) {
    buffer.setShort(flags, (flags() & 0x7) << 13 | value & 0x1FFF);
    return this;
  }

  /**
   * Get TTL.
   *
   * @return returns TTL.
   * @since 1.0.0
   */
  public int ttl() {
    return buffer.getByte(ttl) & 0xFF;
  }

  /**
   * Set TTL.
   *
   * @param value TTL.
   * @return returns this instance.
   * @since 1.0.0
   */
  public Ip4 ttl(int value) {
    buffer.setByte(ttl, value & 0xFF);
    return this;
  }

  /**
   * Get protocol.
   *
   * @return returns protocol.
   * @since 1.0.0
   */
  public int protocol() {
    return buffer.getByte(protocol) & 0xFF;
  }

  /**
   * Set protocol.
   *
   * @param value protocol.
   * @return returns this instance.
   * @since 1.0.0
   */
  public Ip4 protocol(int value) {
    buffer.setByte(protocol, value & 0xFF);
    return this;
  }

  /**
   * Get checksum.
   *
   * @return returns checksum.
   * @since 1.0.0
   */
  public int checksum() {
    return buffer.getShort(headerChecksum) & 0xFFFF;
  }

  /**
   * Set checksum, calculate checksum with {@link Ip4#calculateChecksum()}.
   *
   * @param value checksum.
   * @return returns this instance.
   * @since 1.0.0
   */
  public Ip4 checksum(int value) {
    buffer.setShort(headerChecksum, value & 0xFFFF);
    return this;
  }

  /**
   * Calculate this IPv4 header checksum.
   *
   * @return returns this header checksum.
   * @since 1.0.0
   */
  public int calculateChecksum() {
    int accumulation = Checksum.sum(buffer, offset, ihl() << 2);
    accumulation -= buffer.getShort(headerChecksum) & 0xFFFF;
    accumulation = (accumulation >> 16 & 0xFFFF) + (accumulation & 0xFFFF);
    return (~accumulation & 0xFFFF);
  }

  /**
   * Check if this header has valid checksum value.
   *
   * @return returns {@code true} if valid, {@code false} otherwis.
   * @since 1.0.0
   */
  public boolean isValidChecksum() {
    return checksum() == calculateChecksum();
  }

  /**
   * Get source IP ({@link Inet4Address}).
   *
   * @return returns source IP ({@link Inet4Address}).
   * @since 1.0.0
   */
  public Inet4Address source() {
    return InetAddresses.fromBytesToInet4Address(Bytes.toByteArray(buffer.getInt(source)));
  }

  /**
   * Set source IP ({@link Inet4Address}).
   *
   * @param address source IP ({@link Inet4Address}).
   * @return returns this instance.
   * @since 1.0.0
   */
  public Ip4 source(Inet4Address address) {
    buffer.setBytes(source, address.getAddress());
    return this;
  }

  /**
   * Get destination IP ({@link Inet4Address}).
   *
   * @return returns destination IP ({@link Inet4Address}).
   * @since 1.0.0
   */
  public Inet4Address destination() {
    return InetAddresses.fromBytesToInet4Address(Bytes.toByteArray(buffer.getInt(destination)));
  }

  /**
   * Set destination IP ({@link Inet4Address}.)
   *
   * @param address destination IP ({@link Inet4Address}).
   * @return returns this instance.
   * @since 1.0.0
   */
  public Ip4 destination(Inet4Address address) {
    buffer.setBytes(destination, address.getAddress());
    return this;
  }

  /**
   * Get IPv4 header options.
   *
   * @return returns header options.
   * @since 1.0.0
   */
  public byte[] options() {
    byte[] data = new byte[(ihl() - 5) << 2];
    buffer.getBytes(options, data);
    return data;
  }

  /**
   * Set IPv4 header options.
   *
   * @param value options value.
   * @return returns this instance.
   * @since 1.0.0
   */
  public Ip4 options(byte[] value) {
    int maxLength = (ihl() - 5) << 2;
    buffer.setBytes(options, value, 0, Math.min(value.length, maxLength));
    return this;
  }

  /** {@inheritDoc} */
  @Override
  public int size() {
    if (maxIhl == 0) {
      Validate.notIllegalState(buffer.readableBytes() >= 20, "buffer size is not sufficient.");
      return (buffer.getByte(buffer.readerIndex()) & 0xF) << 2;
    }
    return (buffer.getByte(version) & 0xF) << 2;
  }

  @Override
  public String toString() {
    return Strings.toStringBuilder(this)
        .add("version", version())
        .add("ihl", ihl())
        .add("dscp", dscp())
        .add("ecn", ecn())
        .add("totalLength", totalLength())
        .add("identification", identification())
        .add("flags", flags())
        .add("fragmentOffset", fragmentOffset())
        .add("ttl", ttl())
        .add("protocol", protocol())
        .add("checksum", String.format("0x%s", Integer.toHexString(checksum())))
        .add("source", source().getHostAddress())
        .add("destination", destination().getHostAddress())
        .add("options", String.format("0x%s", Strings.hex(options())))
        .toString();
  }
}
