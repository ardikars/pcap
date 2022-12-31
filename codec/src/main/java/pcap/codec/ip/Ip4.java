/*
 * Copyright (c) 2020-2023 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.codec.ip;

import java.net.Inet4Address;
import java.util.Arrays;
import java.util.Objects;
import pcap.codec.AbstractPacket;
import pcap.common.net.InetAddresses;
import pcap.common.util.Bytes;
import pcap.common.util.Strings;
import pcap.common.util.Validate;
import pcap.spi.PacketBuffer;

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
  private final long versionOffset;
  private final long dscpOffset;
  private final long totalLengthOffset;
  private final long identificationOffset;
  private final long flagsOffset;
  private final long ttlOffset;
  private final long protocolOffset;
  private final long headerChecksumOffset;
  private final long sourceOffset;
  private final long destinationOffset;
  private final long optionsOffset;

  private final int maxIhl;

  private Ip4(PacketBuffer buffer) {
    super(buffer);
    this.versionOffset = superOffset;
    this.dscpOffset = versionOffset + 1;
    this.totalLengthOffset = dscpOffset + 1;
    this.identificationOffset = totalLengthOffset + 2;
    this.flagsOffset = identificationOffset + 2;
    this.ttlOffset = flagsOffset + 2;
    this.protocolOffset = ttlOffset + 1;
    this.headerChecksumOffset = protocolOffset + 1;
    this.sourceOffset = headerChecksumOffset + 2;
    this.destinationOffset = sourceOffset + 4;
    this.optionsOffset = destinationOffset + 4;
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
    return (superBuffer.getByte(versionOffset) >> 4) & 0xF;
  }

  /**
   * Set IP version number (4).
   *
   * @param value version number (4).
   * @return returns this instance.
   * @since 1.0.0
   */
  public Ip4 version(int value) {
    superBuffer.setByte(versionOffset, (value & 0xF) << 4 | ihl());
    return this;
  }

  /**
   * Get IHL.
   *
   * @return returns IHL.
   * @since 1.0.0
   */
  public int ihl() {
    return superBuffer.getByte(versionOffset) & 0xF;
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
    superBuffer.setByte(versionOffset, version() << 4 | value & 0xF);
    return this;
  }

  /**
   * Get DSCP.
   *
   * @return returns DSCP.
   * @since 1.0.0
   */
  public int dscp() {
    return (superBuffer.getByte(dscpOffset) >> 2) & 0x3F;
  }

  /**
   * Set DSCP.
   *
   * @param value DSCP.
   * @return returns this instance.
   * @since 1.0.0
   */
  public Ip4 dscp(int value) {
    superBuffer.setByte(dscpOffset, (value & 0x3F) << 2 | ecn());
    return this;
  }

  /**
   * Get ECN.
   *
   * @return returns ECN.
   * @since 1.0.0
   */
  public int ecn() {
    return superBuffer.getByte(dscpOffset) & 0x3;
  }

  /**
   * Set ECN.
   *
   * @param value ECN.
   * @return returns this instance.
   * @since 1.0.0
   */
  public Ip4 ecn(int value) {
    superBuffer.setByte(dscpOffset, dscp() << 2 | value & 0x3);
    return this;
  }

  /**
   * Get total length.
   *
   * @return returns total length.
   * @since 1.0.0
   */
  public int totalLength() {
    return superBuffer.getShort(totalLengthOffset) & 0xFFFF;
  }

  /**
   * Set total length.
   *
   * @param value total length.
   * @return returns this instance.
   * @since 1.0.0
   */
  public Ip4 totalLength(int value) {
    superBuffer.setShort(totalLengthOffset, value & 0xFFFF);
    return this;
  }

  /**
   * Get identification.
   *
   * @return returns identification.
   * @since 1.0.0
   */
  public int identification() {
    return superBuffer.getShort(identificationOffset) & 0xFFFF;
  }

  /**
   * Set identification.
   *
   * @param value identification.
   * @return returns this instance.
   * @since 1.0.0
   */
  public Ip4 identification(int value) {
    superBuffer.setShort(identificationOffset, value & 0xFFFF);
    return this;
  }

  /**
   * Get flags.
   *
   * @return returns flags.
   * @since 1.0.0
   */
  public int flags() {
    return (superBuffer.getShort(flagsOffset) >> 13) & 0x7;
  }

  /**
   * Set flags.
   *
   * @param value flags.
   * @return this instance.
   * @since 1.0.0
   */
  public Ip4 flags(int value) {
    superBuffer.setShort(flagsOffset, (value & 0x7) << 13 | fragmentOffset());
    return this;
  }

  /**
   * Get fragment offset.
   *
   * @return returns fragment offset.
   * @since 1.0.0
   */
  public int fragmentOffset() {
    return superBuffer.getShort(flagsOffset) & 0x1FFF;
  }

  /**
   * Set fragment offset.
   *
   * @param value fragment offset.
   * @return returns this instance.
   * @since 1.0.0
   */
  public Ip4 fragmentOffset(int value) {
    superBuffer.setShort(flagsOffset, (flags() & 0x7) << 13 | value & 0x1FFF);
    return this;
  }

  /**
   * Get TTL.
   *
   * @return returns TTL.
   * @since 1.0.0
   */
  public int ttl() {
    return superBuffer.getByte(ttlOffset) & 0xFF;
  }

  /**
   * Set TTL.
   *
   * @param value TTL.
   * @return returns this instance.
   * @since 1.0.0
   */
  public Ip4 ttl(int value) {
    superBuffer.setByte(ttlOffset, value & 0xFF);
    return this;
  }

  /**
   * Get protocol.
   *
   * @return returns protocol.
   * @since 1.0.0
   */
  public int protocol() {
    return superBuffer.getByte(protocolOffset) & 0xFF;
  }

  /**
   * Set protocol.
   *
   * @param value protocol.
   * @return returns this instance.
   * @since 1.0.0
   */
  public Ip4 protocol(int value) {
    superBuffer.setByte(protocolOffset, value & 0xFF);
    return this;
  }

  /**
   * Get checksum.
   *
   * @return returns checksum.
   * @since 1.0.0
   */
  public int checksum() {
    return superBuffer.getShort(headerChecksumOffset) & 0xFFFF;
  }

  /**
   * Set checksum, calculate checksum with {@link Ip4#calculateChecksum()}.
   *
   * @param value checksum.
   * @return returns this instance.
   * @since 1.0.0
   */
  public Ip4 checksum(int value) {
    superBuffer.setShort(headerChecksumOffset, value & 0xFFFF);
    return this;
  }

  /**
   * Calculate this IPv4 header checksum.
   *
   * @return returns this header checksum.
   * @since 1.0.0
   */
  public int calculateChecksum() {
    int accumulation = Checksum.sum(superBuffer, superOffset, ihl() << 2);
    accumulation -= superBuffer.getShort(headerChecksumOffset) & 0xFFFF;
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
    return InetAddresses.fromBytesToInet4Address(
        Bytes.toByteArray(superBuffer.getInt(sourceOffset)));
  }

  /**
   * Set source IP ({@link Inet4Address}).
   *
   * @param address source IP ({@link Inet4Address}).
   * @return returns this instance.
   * @since 1.0.0
   */
  public Ip4 source(Inet4Address address) {
    superBuffer.setBytes(sourceOffset, address.getAddress());
    return this;
  }

  /**
   * Get destination IP ({@link Inet4Address}).
   *
   * @return returns destination IP ({@link Inet4Address}).
   * @since 1.0.0
   */
  public Inet4Address destination() {
    return InetAddresses.fromBytesToInet4Address(
        Bytes.toByteArray(superBuffer.getInt(destinationOffset)));
  }

  /**
   * Set destination IP ({@link Inet4Address}.)
   *
   * @param address destination IP ({@link Inet4Address}).
   * @return returns this instance.
   * @since 1.0.0
   */
  public Ip4 destination(Inet4Address address) {
    superBuffer.setBytes(destinationOffset, address.getAddress());
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
    superBuffer.getBytes(optionsOffset, data);
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
    superBuffer.setBytes(optionsOffset, value, 0, Math.min(value.length, maxLength));
    return this;
  }

  /** {@inheritDoc} */
  @Override
  public int size() {
    if (maxIhl == 0) {
      Validate.notIllegalState(superBuffer.readableBytes() >= 20, "buffer size is not sufficient.");
      return (superBuffer.getByte(superBuffer.readerIndex()) & 0xF) << 2;
    }
    return (superBuffer.getByte(versionOffset) & 0xF) << 2;
  }

  @Override
  public boolean equals(Object o) {
    return super.equals(o);
  }

  @Override
  public int hashCode() {
    return Objects.hash(
        super.hashCode(),
        version(),
        ihl(),
        dscp(),
        ecn(),
        totalLength(),
        identification(),
        flags(),
        fragmentOffset(),
        ttl(),
        protocol(),
        checksum(),
        source(),
        destination(),
        Arrays.hashCode(options()));
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
