/*
 * Copyright (c) 2020-2021 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.codec.ip.extension.ip6;

import pcap.codec.AbstractPacket;
import pcap.common.util.Strings;
import pcap.common.util.Validate;
import pcap.spi.PacketBuffer;
import pcap.spi.annotation.Incubating;

@Incubating
public final class Routing extends AbstractPacket {

  private static final int FIXED_ROUTING_DATA_LENGTH = 4;

  private final long nextHeader;
  private final long headerExtensionLength;
  private final long routingType;
  private final long segmentsLeft;
  private final long routingData;

  private final int maxRoutingDataLength;

  private Routing(PacketBuffer buffer) {
    super(buffer);
    this.nextHeader = offset;
    this.headerExtensionLength = nextHeader + 1;
    this.routingType = headerExtensionLength + 1;
    this.segmentsLeft = routingType + 1;
    this.routingData = segmentsLeft + 1;
    this.maxRoutingDataLength =
        FIXED_ROUTING_DATA_LENGTH + 8 * buffer.getByte(headerExtensionLength);
  }

  @Incubating
  public int nextHeader() {
    return buffer.getByte(nextHeader);
  }

  @Incubating
  public Routing nextHeader(int value) {
    buffer.setByte(nextHeader, value);
    return this;
  }

  @Incubating
  public int headerExtensionLength() {
    return buffer.getByte(headerExtensionLength);
  }

  @Incubating
  public Routing headerExtensionLength(int value) {
    buffer.setByte(headerExtensionLength, value);
    return this;
  }

  @Incubating
  public int routingType() {
    return buffer.getByte(routingType);
  }

  @Incubating
  public Routing routingType(int value) {
    buffer.setByte(routingType, value);
    return this;
  }

  @Incubating
  public int segmentsLeft() {
    return buffer.getByte(segmentsLeft);
  }

  @Incubating
  public Routing segmentsLeft(int value) {
    buffer.setByte(segmentsLeft, value);
    return this;
  }

  @Incubating
  public byte[] routingData() {
    byte[] bytes = new byte[FIXED_ROUTING_DATA_LENGTH + 8 * buffer.getByte(headerExtensionLength)];
    buffer.getBytes(routingData, bytes);
    return bytes;
  }

  @Incubating
  public Routing routingData(byte[] value) {
    buffer.setBytes(routingData, value, 0, Math.min(value.length, maxRoutingDataLength));
    return this;
  }

  @Override
  public int size() {
    if (maxRoutingDataLength == 0) {
      Validate.notIllegalState(buffer.readableBytes() >= 8, "buffer size is not sufficient.");
    }
    return 4 + FIXED_ROUTING_DATA_LENGTH + 8 * buffer.getByte(headerExtensionLength);
  }

  @Override
  public String toString() {
    return Strings.toStringBuilder(this)
        .add("nextHeader", nextHeader())
        .add("headerExtensionLength", headerExtensionLength())
        .add("routingType", routingType())
        .add("segmentsLeft", segmentsLeft())
        .add("routingData", routingData())
        .toString();
  }
}
