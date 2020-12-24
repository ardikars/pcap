/*
 * Copyright (c) 2020 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.codec.ip;

import java.net.Inet6Address;
import pcap.codec.AbstractPacket;
import pcap.common.net.InetAddresses;
import pcap.common.util.Strings;
import pcap.common.util.Validate;
import pcap.spi.PacketBuffer;
import pcap.spi.annotation.Incubating;

/**
 * IPv6
 *
 * @since 1.0.0 (incubating)
 */
@Incubating
public final class Ip6 extends AbstractPacket {

  public static final int TYPE = 0x86dd;

  // Header fields offset.
  private final long version;
  private final long payloadLength;
  private final long nextHeader;
  private final long hopLimit;
  private final long source;
  private final long destination;

  private Ip6(PacketBuffer buffer) {
    super(buffer);
    this.version = offset;
    this.payloadLength = version + 4;
    this.nextHeader = payloadLength + 2;
    this.hopLimit = nextHeader + 1;
    this.source = hopLimit + 1;
    this.destination = source + 16;
  }

  /**
   * Wrap buffer into {@link Ip6}.
   *
   * @param size {@link Ip6} header size.
   * @param buffer buffer.
   * @return returns {@link Ip6} instance.
   * @since 1.0.0 (incubating)
   */
  public static Ip6 newInstance(int size, PacketBuffer buffer) {
    Validate.notIllegalArgument(
        size == 40 && buffer.readableBytes() >= 40, "buffer size is not sufficient.");
    return new Ip6(buffer);
  }

  /**
   * Get IP version number (6).
   *
   * @return returns IP version number (6).
   * @since 1.0.0 (incubating)
   */
  public int version() {
    return (buffer.getInt(version) >> 28) & 0xF;
  }

  /**
   * Set IP version number (6).
   *
   * @param value IP version number (6).
   * @return returns this instance.
   * @since 1.0.0 (incubating)
   */
  public Ip6 version(int value) {
    int v = buffer.getInt(version);
    buffer.setInt(version, (value & 0xF) << 28 | ((v >> 20) & 0xFF) << 20 | v & 0xFFFFF);
    return this;
  }

  /**
   * Get traffic class.
   *
   * @return returns traffic class.
   * @since 1.0.0 (incubating)
   */
  public int trafficClass() {
    return (buffer.getInt(version) >> 20) & 0xFF;
  }

  /**
   * Set traffic class.
   *
   * @param value traffic class.
   * @return returns this instance.
   * @since 1.0.0 (incubating)
   */
  public Ip6 trafficClass(int value) {
    int v = buffer.getInt(version);
    buffer.setInt(version, ((v >> 28) & 0xF) << 28 | (value & 0xFF) << 20 | v & 0xFFFFF);
    return this;
  }

  /**
   * Flow label.
   *
   * @return returns flow label.
   * @since 1.0.0 (incubating)
   */
  public int flowLabel() {
    return (buffer.getInt(version) & 0xFFFFF);
  }

  /**
   * Set flow label.
   *
   * @param value flow label.
   * @return flow label.
   * @since 1.0.0 (incubating)
   */
  public Ip6 flowLabel(int value) {
    int v = buffer.getInt(version);
    buffer.setInt(version, ((v >> 28) & 0xF) << 28 | ((v >> 20) & 0xFF) << 20 | value & 0xFFFFF);
    return this;
  }

  /**
   * Get payload length.
   *
   * @return returns payload length.
   * @since 1.0.0 (incubating)
   */
  public int payloadLength() {
    return buffer.getShort(payloadLength) & 0xFFFF;
  }

  /**
   * Set payload length.
   *
   * @param value payload length.
   * @return returns this instance.
   * @since 1.0.0 (incubating)
   */
  public Ip6 payloadLength(int value) {
    buffer.setShort(payloadLength, value & 0xFFFF);
    return this;
  }

  /**
   * Get next header type.
   *
   * @return returns next header type.
   * @since 1.0.0 (incubating)
   */
  public int nextHeader() {
    return buffer.getByte(nextHeader) & 0xFF;
  }

  /**
   * Set next header type.
   *
   * @param value next header type.
   * @return returns this instance.
   * @since 1.0.0 (incubating)
   */
  public Ip6 nextHeader(int value) {
    buffer.setByte(nextHeader, value & 0xFF);
    return this;
  }

  /**
   * Get hop limit.
   *
   * @return returns hop limit.
   * @since 1.0.0 (incubating)
   */
  public int hopLimit() {
    return buffer.getByte(hopLimit) & 0xFF;
  }

  /**
   * Set hop limit.
   *
   * @param value hop limit.
   * @return returns this instance.
   * @since 1.0.0 (incubating)
   */
  public Ip6 hopLimit(int value) {
    buffer.setByte(hopLimit, value & 0xFF);
    return this;
  }

  /**
   * Get source IP ({@link Inet6Address}.
   *
   * @return returns source IP ({@link Inet6Address}).
   * @since 1.0.0 (incubating)
   */
  public Inet6Address source() {
    return getInet6Address(source);
  }

  /**
   * Set source IP ({@link Inet6Address}).
   *
   * @param value source IP ({@link Inet6Address}).
   * @return returns this instance.
   * @since 1.0.0 (incubating)
   */
  public Ip6 source(Inet6Address value) {
    buffer.setBytes(source, value.getAddress());
    return this;
  }

  /**
   * Get destination IP ({@link Inet6Address}).
   *
   * @return returns destination IP ({@link Inet6Address}).
   * @since 1.0.0 (incubating)
   */
  public Inet6Address destination() {
    return getInet6Address(destination);
  }

  /**
   * Set destination IP ({@link Inet6Address}).
   *
   * @param value destination IP ({@link Inet6Address}).
   * @return returns this instance.
   * @since 1.0.0 (incubating)
   */
  public Ip6 destination(Inet6Address value) {
    buffer.setBytes(destination, value.getAddress());
    return this;
  }

  private Inet6Address getInet6Address(long offset) {
    byte[] address = new byte[16];
    buffer.getBytes(offset, address);
    return InetAddresses.fromBytesToInet6Address(address);
  }

  /** {@inheritDoc} */
  @Override
  public int size() {
    return 40;
  }

  @Override
  public String toString() {
    return Strings.toStringBuilder(this)
        .add("version", version())
        .add("trafficClass", trafficClass())
        .add("flowLabel", flowLabel())
        .add("payloadLength", payloadLength())
        .add("nextHeader", nextHeader())
        .add("hopLimit", hopLimit())
        .add("source", source().getHostAddress())
        .add("destination", destination().getHostAddress())
        .toString();
  }
}
