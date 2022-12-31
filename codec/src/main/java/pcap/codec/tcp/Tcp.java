/*
 * Copyright (c) 2020-2023 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.codec.tcp;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.util.Arrays;
import java.util.Objects;
import pcap.codec.AbstractPacket;
import pcap.common.util.Strings;
import pcap.common.util.Validate;
import pcap.spi.PacketBuffer;

/*
   0                   1                   2                   3
   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |          Source Port          |       Destination Port        |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                        Sequence Number                        |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                    Acknowledgment Number                      |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |  Data |           |U|A|P|R|S|F|                               |
  | Offset| Reserved  |R|C|S|S|Y|I|            Window             |
  |       |           |G|K|H|T|N|N|                               |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |           Checksum            |         Urgent Pointer        |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                    Options                    |    Padding    |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                             data                              |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
/**
 * TCP
 *
 * @since 1.0.0
 */
public final class Tcp extends AbstractPacket {

  public static final int TYPE = 6;

  // Header fields offset.
  private final long sourcePortOffset;
  private final long destinationPortOffset;
  private final long sequenceNumberOffset;
  private final long acknowledgmentNumberOffset;
  private final long dataOffset;
  private final long windowSizeOffset;
  private final long checksumOffset;
  private final long urgentPointerOffset;
  private final long optionsOffset;

  private final long maxDataOffset;

  private Tcp(PacketBuffer buffer) {
    super(buffer);
    this.sourcePortOffset = superOffset;
    this.destinationPortOffset = sourcePortOffset + 2;
    this.sequenceNumberOffset = destinationPortOffset + 2;
    this.acknowledgmentNumberOffset = sequenceNumberOffset + 4;
    this.dataOffset = acknowledgmentNumberOffset + 4;
    this.windowSizeOffset = dataOffset + 2;
    this.checksumOffset = windowSizeOffset + 2;
    this.urgentPointerOffset = checksumOffset + 2;
    this.optionsOffset = urgentPointerOffset + 2;
    this.maxDataOffset = dataOffset();
  }

  /**
   * Wrap buffer into {@link Tcp}.
   *
   * @param size {@link Tcp} header size.
   * @param buffer buffer.
   * @return returns {@link Tcp} instance.
   * @since 1.0.0
   */
  public static Tcp newInstance(int size, PacketBuffer buffer) {
    Validate.notIllegalArgument(
        size >= 20 && size <= 60 && buffer.readableBytes() >= 20, "buffer size is not sufficient.");
    int flags = buffer.getShort(buffer.readerIndex() + 12) & 0x1FF;
    buffer.setShort(buffer.readerIndex() + 12, flags & 0x1FF | (size >> 2) << 12);
    return new Tcp(buffer);
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
  public Tcp sourcePort(int value) {
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
  public Tcp destinationPort(int value) {
    superBuffer.setShort(destinationPortOffset, value & 0xFFFF);
    return this;
  }

  /**
   * Get sequence number.
   *
   * @return returns sequence number.
   * @since 1.0.0
   */
  public long sequenceNumber() {
    return superBuffer.getUnsignedInt(sequenceNumberOffset);
  }

  /**
   * Set sequence number.
   *
   * @param value sequence number.
   * @return returns this instance.
   * @since 1.0.0
   */
  public Tcp sequenceNumber(int value) {
    superBuffer.setInt(sequenceNumberOffset, value);
    return this;
  }

  /**
   * Get acknowledgment number.
   *
   * @return returns acknowledgment number.
   * @since 1.0.0
   */
  public long acknowledgmentNumber() {
    return superBuffer.getUnsignedInt(acknowledgmentNumberOffset);
  }

  /**
   * Set acknowledgment number.
   *
   * @param value acknowledgment number.
   * @return returns this instance.
   * @since 1.0.0
   */
  public Tcp acknowledgmentNumber(int value) {
    superBuffer.setInt(acknowledgmentNumberOffset, value);
    return this;
  }

  /**
   * Get data offset.
   *
   * @return returns data offset.
   * @since 1.0.0
   */
  public int dataOffset() {
    return (superBuffer.getShort(dataOffset) >> 12) & 0xF;
  }

  /**
   * Set data offset.
   *
   * @param value data offset.
   * @return returns this instance.
   * @since 1.0.0
   */
  public Tcp dataOffset(int value) {
    if (value < 5 || value > maxDataOffset) {
      throw new IllegalArgumentException(
          String.format("value: %d (expected: 5 >= value <= %d)", value, maxDataOffset));
    }
    int val = getShortFlags() & 0x1FF | (value & 0xF) << 12;
    superBuffer.setShort(dataOffset, val);
    return this;
  }

  /**
   * Get NS flag.
   *
   * @return returns {@code true} if is set, {@code false} otherwise.
   * @since 1.3.0
   */
  public boolean isNs() {
    return (((superBuffer.getShort(dataOffset) & 0x1FF) >> 8) & 0x1) == 1;
  }

  /**
   * Set NS flag.
   *
   * @param value {@code true} for set NS flag, {@code false} otherwise.
   * @return returns this instance.
   * @since 1.0.0
   */
  public Tcp ns(boolean value) {
    if (isNs() != value) {
      setShortFlags(value ? 256 : -256);
    }
    return this;
  }

  /**
   * Get CWR flag.
   *
   * @return returns {@code true} if is set, {@code false} otherwise.
   * @since 1.3.0
   */
  public boolean isCwr() {
    return (((superBuffer.getShort(dataOffset) & 0x1FF) >> 7) & 0x1) == 1;
  }

  /**
   * Set CWR flag.
   *
   * @param value {@code true} for set CWR flag, {@code false} otherwise.
   * @return returns this instance.
   * @since 1.0.0
   */
  public Tcp cwr(boolean value) {
    if (isCwr() != value) {
      setShortFlags(value ? 128 : -128);
    }
    return this;
  }

  /**
   * Get ECE flag.
   *
   * @return returns {@code true} if is set, {@code false} otherwise.
   * @since 1.3.0
   */
  public boolean isEce() {
    return (((superBuffer.getShort(dataOffset) & 0x1FF) >> 6) & 0x1) == 1;
  }

  /**
   * Set ECE flag.
   *
   * @param value {@code true} for set ECE flag, {@code false} otherwise.
   * @return returns this instance.
   * @since 1.0.0
   */
  public Tcp ece(boolean value) {
    if (isEce() != value) {
      setShortFlags(value ? 64 : -64);
    }
    return this;
  }

  /**
   * Get URG flag.
   *
   * @return returns {@code true} if is set, {@code false} otherwise.
   * @since 1.3.0
   */
  public boolean isUrg() {
    return (((superBuffer.getShort(dataOffset) & 0x1FF) >> 5) & 0x1) == 1;
  }

  /**
   * Set URG flag.
   *
   * @param value {@code true} for set URG flag, {@code false} otherwise.
   * @return returns this instance.
   * @since 1.0.0
   */
  public Tcp urg(boolean value) {
    if (isUrg() != value) {
      setShortFlags(value ? 32 : -32);
    }
    return this;
  }

  /**
   * Get ACK flag.
   *
   * @return returns {@code true} if is set, {@code false} otherwise.
   * @since 1.3.0
   */
  public boolean isAck() {
    return (((superBuffer.getShort(dataOffset) & 0x1FF) >> 4) & 0x1) == 1;
  }

  /**
   * Set ACK flag.
   *
   * @param value {@code true} for set ACK flag, {@code false} otherwise.
   * @return returns this instance.
   * @since 1.0.0
   */
  public Tcp ack(boolean value) {
    if (isAck() != value) {
      setShortFlags(value ? 16 : -16);
    }
    return this;
  }

  /**
   * Get PSH flag.
   *
   * @return returns {@code true} if is set, {@code false} otherwise.
   * @since 1.3.0
   */
  public boolean isPsh() {
    return (((superBuffer.getShort(dataOffset) & 0x1FF) >> 3) & 0x1) == 1;
  }

  /**
   * Set PSH flag.
   *
   * @param value {@code true} for set PSH flag, {@code false} otherwise.
   * @return returns this instance.
   * @since 1.0.0
   */
  public Tcp psh(boolean value) {
    if (isPsh() != value) {
      setShortFlags(value ? 8 : -8);
    }
    return this;
  }

  /**
   * Get RST flag.
   *
   * @return returns {@code true} if is set, {@code false} otherwise.
   * @since 1.3.0
   */
  public boolean isRst() {
    return (((superBuffer.getShort(dataOffset) & 0x1FF) >> 2) & 0x1) == 1;
  }

  /**
   * Set RST flag.
   *
   * @param value {@code true} for set RST flag, {@code false} otherwise.
   * @return returns this instance.
   * @since 1.0.0
   */
  public Tcp rst(boolean value) {
    if (isRst() != value) {
      setShortFlags(value ? 4 : -4);
    }
    return this;
  }

  /**
   * Get SYN flag.
   *
   * @return returns {@code true} if is set, {@code false} otherwise.
   * @since 1.3.0
   */
  public boolean isSyn() {
    return (((superBuffer.getShort(dataOffset) & 0x1FF) >> 1) & 0x1) == 1;
  }

  /**
   * Set SYN flag.
   *
   * @param value {@code true} for set SYN flag, {@code false} otherwise.
   * @return returns this instance.
   * @since 1.0.0
   */
  public Tcp syn(boolean value) {
    if (isSyn() != value) {
      setShortFlags(value ? 2 : -2);
    }
    return this;
  }

  /**
   * Get FIN flag.
   *
   * @return returns {@code true} if is set, {@code false} otherwise.
   * @since 1.3.0
   */
  public boolean isFin() {
    return ((superBuffer.getShort(dataOffset) & 0x1FF) & 0x1) == 1;
  }

  /**
   * Set FIN flag.
   *
   * @param value {@code true} for set FIN flag, {@code false} otherwise.
   * @return returns this instance.
   * @since 1.0.0
   */
  public Tcp fin(boolean value) {
    if (isFin() != value) {
      setShortFlags(value ? 1 : -1);
    }
    return this;
  }

  /**
   * Get window size.
   *
   * @return returns window size.
   * @since 1.0.0
   */
  public int windowSize() {
    return superBuffer.getShort(windowSizeOffset) & 0xFFFF;
  }

  /**
   * Set window size.
   *
   * @param value window size.
   * @return returns this instance.
   * @since 1.0.0
   */
  public Tcp windowSize(int value) {
    superBuffer.setShort(windowSizeOffset, value & 0xFFFF);
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
   * Set checksum, calculate checksum with {@link Tcp#calculateChecksum(InetAddress, InetAddress,
   * int)}.
   *
   * @param value checksum
   * @return returns this instance.
   * @since 1.0.0
   */
  public Tcp checksum(int value) {
    superBuffer.setShort(checksumOffset, value & 0xFFFF);
    return this;
  }

  /**
   * Calculate this header checksum.
   *
   * @param srcAddr source IP address.
   * @param dstAddr destination IP address.
   * @param payloadLength payload length.
   * @return returns checksum.
   * @since 1.0.0
   */
  public int calculateChecksum(InetAddress srcAddr, InetAddress dstAddr, int payloadLength) {
    return Checksum.calculate(
        superBuffer, superOffset, srcAddr, dstAddr, TYPE, size(), payloadLength);
  }

  /**
   * Check if this header has valid checksum.
   *
   * @param src source IP address.
   * @param dst destination IP address.
   * @param payloadLength payload length.
   * @return returns {@code true} if valid, {@code false} otherwise.
   * @since 1.0.0
   */
  public boolean isValidChecksum(Inet4Address src, Inet4Address dst, int payloadLength) {
    return calculateChecksum(src, dst, payloadLength) == 0;
  }

  /**
   * Get urgent pointer.
   *
   * @return returns urgent pointer.
   * @since 1.0.0
   */
  public int urgentPointer() {
    return superBuffer.getShort(urgentPointerOffset) & 0xFFFF;
  }

  /**
   * Set urgent pointer.
   *
   * @param value urgent pointer.
   * @return returns this instance.
   * @since 1.0.0
   */
  public Tcp urgentPointer(int value) {
    superBuffer.setShort(urgentPointerOffset, value & 0xFFFF);
    return this;
  }

  /**
   * Get header options.
   *
   * @return returns header options.
   * @since 1.0.0
   */
  public byte[] options() {
    byte[] data = new byte[(dataOffset() << 2) - 20];
    superBuffer.getBytes(optionsOffset, data, 0, data.length);
    return data;
  }

  /**
   * Set header options.
   *
   * @param value options value.
   * @return returns this instance.
   * @since 1.0.0
   */
  public Tcp options(byte[] value) {
    int maxLength = (dataOffset() - 5) << 2;
    superBuffer.setBytes(optionsOffset, value, 0, Math.min(value.length, maxLength));
    return this;
  }

  private short getShortFlags() {
    int val = superBuffer.getShort(dataOffset) & 0x1FF;
    short flags = 0;
    for (int i = 8; i >= 0; i--) {
      if (((val >> i) & 0x1) == 1) {
        flags += 1 << i;
      }
    }
    return flags;
  }

  private void setShortFlags(int flags) {
    int val = (getShortFlags() + flags) & 0x1FF | dataOffset() << 12;
    superBuffer.setShort(dataOffset, val);
  }

  /** {@inheritDoc} */
  @Override
  public int size() {
    if (maxDataOffset == 0) {
      Validate.notIllegalState(superBuffer.readableBytes() >= 20, "buffer size is not sufficient.");
      return ((superBuffer.getShort(superBuffer.readerIndex() + 12) >> 12) & 0xF) << 2;
    }
    return dataOffset() << 2;
  }

  @Override
  public boolean equals(Object o) {
    return super.equals(o);
  }

  @Override
  public int hashCode() {
    return Objects.hash(
        super.hashCode(),
        sourcePort(),
        destinationPort(),
        sequenceNumber(),
        acknowledgmentNumber(),
        dataOffset(),
        isNs(),
        isCwr(),
        isEce(),
        isUrg(),
        isAck(),
        isPsh(),
        isRst(),
        isSyn(),
        isFin(),
        windowSize(),
        checksum(),
        urgentPointer(),
        Arrays.hashCode(options()));
  }

  @Override
  public String toString() {
    short v = superBuffer.getShort(dataOffset);
    return Strings.toStringBuilder(this)
        .add("sourcePort", sourcePort())
        .add("destinationPort", destinationPort())
        .add("sequenceNumber", sequenceNumber())
        .add("acknowledgmentNumber", acknowledgmentNumber())
        .add("dataOffset", (v >> 12) & 0xF)
        .add("ns", (((v & 0x1FF) >> 8) & 0x1) == 1)
        .add("cwr", (((v & 0x1FF) >> 7) & 0x1) == 1)
        .add("ece", (((v & 0x1FF) >> 6) & 0x1) == 1)
        .add("urg", (((v & 0x1FF) >> 5) & 0x1) == 1)
        .add("ack", (((v & 0x1FF) >> 4) & 0x1) == 1)
        .add("psh", (((v & 0x1FF) >> 3) & 0x1) == 1)
        .add("rst", (((v & 0x1FF) >> 2) & 0x1) == 1)
        .add("syn", (((v & 0x1FF) >> 1) & 0x1) == 1)
        .add("fin", ((v & 0x1FF) & 0x1) == 1)
        .add("windowsSize", windowSize())
        .add("checksum", String.format("0x%s", Integer.toHexString(checksum())))
        .add("urgentPointer", urgentPointer())
        .add("options", String.format("0x%s", Strings.hex(options())))
        .toString();
  }
}
