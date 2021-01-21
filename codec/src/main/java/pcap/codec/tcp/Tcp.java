/*
 * Copyright (c) 2020-2021 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.codec.tcp;

import java.net.Inet4Address;
import java.net.InetAddress;
import pcap.codec.AbstractPacket;
import pcap.common.util.Strings;
import pcap.common.util.Validate;
import pcap.spi.PacketBuffer;
import pcap.spi.annotation.Incubating;

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
 * @since 1.0.0 (incubating)
 */
@Incubating
public final class Tcp extends AbstractPacket {

  public static final int TYPE = 6;

  // Header fields offset.
  private final long sourcePort;
  private final long destinationPort;
  private final long sequenceNumber;
  private final long acknowledgmentNumber;
  private final long dataOffset;
  private final long windowSize;
  private final long checksum;
  private final long urgentPointer;
  private final long options;

  private final long maxDataOffset;

  private Tcp(PacketBuffer buffer) {
    super(buffer);
    this.sourcePort = offset;
    this.destinationPort = sourcePort + 2;
    this.sequenceNumber = destinationPort + 2;
    this.acknowledgmentNumber = sequenceNumber + 4;
    this.dataOffset = acknowledgmentNumber + 4;
    this.windowSize = dataOffset + 2;
    this.checksum = windowSize + 2;
    this.urgentPointer = checksum + 2;
    this.options = urgentPointer + 2;
    this.maxDataOffset = dataOffset();
  }

  /**
   * Wrap buffer into {@link Tcp}.
   *
   * @param size {@link Tcp} header size.
   * @param buffer buffer.
   * @return returns {@link Tcp} instance.
   * @since 1.0.0 (incubating)
   */
  @Incubating
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
  public Tcp sourcePort(int value) {
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
  public Tcp destinationPort(int value) {
    buffer.setShort(destinationPort, value & 0xFFFF);
    return this;
  }

  /**
   * Get sequence number.
   *
   * @return returns sequence number.
   * @since 1.0.0 (incubating)
   */
  @Incubating
  public long sequenceNumber() {
    return buffer.getUnsignedInt(sequenceNumber);
  }

  /**
   * Set sequence number.
   *
   * @param value sequence number.
   * @return returns this instance.
   * @since 1.0.0 (incubating)
   */
  @Incubating
  public Tcp sequenceNumber(int value) {
    buffer.setInt(sequenceNumber, value);
    return this;
  }

  /**
   * Get acknowledgment number.
   *
   * @return returns acknowledgment number.
   * @since 1.0.0 (incubating)
   */
  @Incubating
  public long acknowledgmentNumber() {
    return buffer.getUnsignedInt(acknowledgmentNumber);
  }

  /**
   * Set ackowledgment number.
   *
   * @param value acknowledgment number.
   * @return returns this instance.
   * @since 1.0.0 (incubating)
   */
  @Incubating
  public Tcp acknowledgmentNumber(int value) {
    buffer.setInt(acknowledgmentNumber, value);
    return this;
  }

  /**
   * Get data offset.
   *
   * @return returns data offset.
   * @since 1.0.0 (incubating)
   */
  @Incubating
  public int dataOffset() {
    return (buffer.getShort(dataOffset) >> 12) & 0xF;
  }

  /**
   * Set data offset.
   *
   * @param value data offset.
   * @return returns this instance.
   * @since 1.0.0 (incubating)
   */
  @Incubating
  public Tcp dataOffset(int value) {
    if (value < 5 || value > maxDataOffset) {
      throw new IllegalArgumentException(
          String.format("value: %d (expected: 5 >= value <= %d)", value, maxDataOffset));
    }
    int val = getShortFlags() & 0x1FF | (value & 0xF) << 12;
    buffer.setShort(dataOffset, val);
    return this;
  }

  /**
   * Get NS flag.
   *
   * @return returns {@code true} if is set, {@code false} otherwise.
   * @since 1.0.0 (incubating)
   */
  @Incubating
  public boolean ns() {
    return (((buffer.getShort(dataOffset) & 0x1FF) >> 8) & 0x1) == 1;
  }

  /**
   * Set NS flag.
   *
   * @param value {@code true} for set NS flag, {@code false} otherwise.
   * @return returns this instance.
   * @since 1.0.0 (incubating)
   */
  @Incubating
  public Tcp ns(boolean value) {
    if (ns() != value) {
      setShortFlags(value ? 256 : -256);
    }
    return this;
  }

  /**
   * Get CWR flag.
   *
   * @return returns {@code true} if is set, {@code false} otherwise.
   * @since 1.0.0 (incubating)
   */
  @Incubating
  public boolean cwr() {
    return (((buffer.getShort(dataOffset) & 0x1FF) >> 7) & 0x1) == 1;
  }

  /**
   * Set CWR flag.
   *
   * @param value {@code true} for set CWR flag, {@code false} otherwise.
   * @return returns this instance.
   * @since 1.0.0 (incubating)
   */
  @Incubating
  public Tcp cwr(boolean value) {
    if (cwr() != value) {
      setShortFlags(value ? 128 : -128);
    }
    return this;
  }

  /**
   * Get ECE flag.
   *
   * @return returns {@code true} if is set, {@code false} otherwise.
   * @since 1.0.0 (incubating)
   */
  @Incubating
  public boolean ece() {
    return (((buffer.getShort(dataOffset) & 0x1FF) >> 6) & 0x1) == 1;
  }

  /**
   * Set ECE flag.
   *
   * @param value {@code true} for set ECE flag, {@code false} otherwise.
   * @return returns this instance.
   * @since 1.0.0 (incubating)
   */
  @Incubating
  public Tcp ece(boolean value) {
    if (ece() != value) {
      setShortFlags(value ? 64 : -64);
    }
    return this;
  }

  /**
   * Get URG flag.
   *
   * @return returns {@code true} if is set, {@code false} otherwise.
   * @since 1.0.0 (incubating)
   */
  @Incubating
  public boolean urg() {
    return (((buffer.getShort(dataOffset) & 0x1FF) >> 5) & 0x1) == 1;
  }

  /**
   * Set URG flag.
   *
   * @param value {@code true} for set URG flag, {@code false} otherwise.
   * @return returns this instance.
   * @since 1.0.0 (incubating)
   */
  @Incubating
  public Tcp urg(boolean value) {
    if (urg() != value) {
      setShortFlags(value ? 32 : -32);
    }
    return this;
  }

  /**
   * Get ACK flag.
   *
   * @return returns {@code true} if is set, {@code false} otherwise.
   * @since 1.0.0 (incubating)
   */
  @Incubating
  public boolean ack() {
    return (((buffer.getShort(dataOffset) & 0x1FF) >> 4) & 0x1) == 1;
  }

  /**
   * Set ACK flag.
   *
   * @param value {@code true} for set ACK flag, {@code false} otherwise.
   * @return returns this instance.
   * @since 1.0.0 (incubating)
   */
  @Incubating
  public Tcp ack(boolean value) {
    if (ack() != value) {
      setShortFlags(value ? 16 : -16);
    }
    return this;
  }

  /**
   * Get PSH flag.
   *
   * @return returns {@code true} if is set, {@code false} otherwise.
   * @since 1.0.0 (incubating)
   */
  @Incubating
  public boolean psh() {
    return (((buffer.getShort(dataOffset) & 0x1FF) >> 3) & 0x1) == 1;
  }

  /**
   * Set PSH flag.
   *
   * @param value {@code true} for set PSH flag, {@code false} otherwise.
   * @return returns this instance.
   * @since 1.0.0 (incubating)
   */
  @Incubating
  public Tcp psh(boolean value) {
    if (psh() != value) {
      setShortFlags(value ? 8 : -8);
    }
    return this;
  }

  /**
   * Get RST flag.
   *
   * @return returns {@code true} if is set, {@code false} otherwise.
   * @since 1.0.0 (incubating)
   */
  @Incubating
  public boolean rst() {
    return (((buffer.getShort(dataOffset) & 0x1FF) >> 2) & 0x1) == 1;
  }

  /**
   * Set RST flag.
   *
   * @param value {@code true} for set RST flag, {@code false} otherwise.
   * @return returns this instance.
   * @since 1.0.0 (incubating)
   */
  @Incubating
  public Tcp rst(boolean value) {
    if (rst() != value) {
      setShortFlags(value ? 4 : -4);
    }
    return this;
  }

  /**
   * Get SYN flag.
   *
   * @return returns {@code true} if is set, {@code false} otherwise.
   * @since 1.0.0 (incubating)
   */
  @Incubating
  public boolean syn() {
    return (((buffer.getShort(dataOffset) & 0x1FF) >> 1) & 0x1) == 1;
  }

  /**
   * Set SYN flag.
   *
   * @param value {@code true} for set SYN flag, {@code false} otherwise.
   * @return returns this instance.
   * @since 1.0.0 (incubating)
   */
  @Incubating
  public Tcp syn(boolean value) {
    if (syn() != value) {
      setShortFlags(value ? 2 : -2);
    }
    return this;
  }

  /**
   * Get FIN flag.
   *
   * @return returns {@code true} if is set, {@code false} otherwise.
   * @since 1.0.0 (incubating)
   */
  @Incubating
  public boolean fin() {
    return ((buffer.getShort(dataOffset) & 0x1FF) & 0x1) == 1;
  }

  /**
   * Set FIN flag.
   *
   * @param value {@code true} for set FIN flag, {@code false} otherwise.
   * @return returns this instance.
   * @since 1.0.0 (incubating)
   */
  @Incubating
  public Tcp fin(boolean value) {
    if (fin() != value) {
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
  @Incubating
  public int windowSize() {
    return buffer.getShort(windowSize) & 0xFFFF;
  }

  /**
   * Set window size.
   *
   * @param value window size.
   * @return returns this instance.
   * @since 1.0.0
   */
  @Incubating
  public Tcp windowSize(int value) {
    buffer.setShort(windowSize, value & 0xFFFF);
    return this;
  }

  /**
   * Get checksum.
   *
   * @return returns checksum.
   * @since 1.0.0
   */
  @Incubating
  public int checksum() {
    return buffer.getShort(checksum) & 0xFFFF;
  }

  /**
   * Set checksum, calculate checksum with {@link Tcp#calculateChecksum(InetAddress, InetAddress,
   * int)}.
   *
   * @param value checksum
   * @return returns this instance.
   * @since 1.0.0
   */
  @Incubating
  public Tcp checksum(int value) {
    buffer.setShort(checksum, value & 0xFFFF);
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
  @Incubating
  public int calculateChecksum(InetAddress srcAddr, InetAddress dstAddr, int payloadLength) {
    return Checksum.calculate(buffer, offset, srcAddr, dstAddr, TYPE, size(), payloadLength);
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
  @Incubating
  public boolean isValidChecksum(Inet4Address src, Inet4Address dst, int payloadLength) {
    return calculateChecksum(src, dst, payloadLength) == 0;
  }

  /**
   * Get urgent pointer.
   *
   * @return returns urgent pointer.
   * @since 1.0.0
   */
  @Incubating
  public int urgentPointer() {
    return buffer.getShort(urgentPointer) & 0xFFFF;
  }

  /**
   * Set urgent pointer.
   *
   * @param value urgent pointer.
   * @return returns this instance.
   * @since 1.0.0
   */
  @Incubating
  public Tcp urgentPointer(int value) {
    buffer.setShort(urgentPointer, value & 0xFFFF);
    return this;
  }

  /**
   * Get header options.
   *
   * @return returns header options.
   * @since 1.0.0
   */
  @Incubating
  public byte[] options() {
    byte[] data = new byte[(dataOffset() << 2) - 20];
    buffer.getBytes(options, data, 0, data.length);
    return data;
  }

  /**
   * Set header options.
   *
   * @param value options value.
   * @return returns this instance.
   * @since 1.0.0
   */
  @Incubating
  public Tcp options(byte[] value) {
    int maxLength = (dataOffset() - 5) << 2;
    buffer.setBytes(options, value, 0, Math.min(value.length, maxLength));
    return this;
  }

  private short getShortFlags() {
    int val = buffer.getShort(dataOffset) & 0x1FF;
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
    buffer.setShort(dataOffset, val);
  }

  /** {@inheritDoc} */
  @Override
  public int size() {
    if (maxDataOffset == 0) {
      Validate.notIllegalState(buffer.readableBytes() >= 20, "buffer size is not sufficient.");
      return ((buffer.getShort(buffer.readerIndex() + 12) >> 12) & 0xF) << 2;
    }
    return dataOffset() << 2;
  }

  @Override
  public String toString() {
    short v = buffer.getShort(dataOffset);
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
        .add("checksum", "0x" + Integer.toHexString(checksum()))
        .add("urgentPointer", urgentPointer())
        .add("options", "0x" + Strings.hex(options()))
        .toString();
  }
}
