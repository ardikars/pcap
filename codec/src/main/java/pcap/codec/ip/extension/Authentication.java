/*
 * Copyright (c) 2020-2021 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.codec.ip.extension;

import pcap.codec.AbstractPacket;
import pcap.common.util.Validate;
import pcap.spi.PacketBuffer;
import pcap.spi.annotation.Incubating;

@Incubating
public final class Authentication extends AbstractPacket {

  private final long nextHeader;
  private final long payloadLength;
  private final long securityParameterIndex;
  private final long sequenceNumber;
  private final long integrityCheckValue;

  private final int maxIcv;

  private Authentication(PacketBuffer buffer) {
    super(buffer);
    this.nextHeader = offset;
    this.payloadLength = nextHeader + 1;
    this.securityParameterIndex = payloadLength + 1 + 2;
    this.sequenceNumber = securityParameterIndex + 4;
    this.integrityCheckValue = sequenceNumber + 4;
    this.maxIcv = (payloadLength() + 2) * 4 - 12;
  }

  @Incubating
  public int nextHeader() {
    return buffer.getByte(nextHeader);
  }

  @Incubating
  public Authentication nextHeader(int value) {
    buffer.setByte(nextHeader, value);
    return this;
  }

  @Incubating
  public int payloadLength() {
    return buffer.getByte(payloadLength);
  }

  @Incubating
  public Authentication payloadLength(int value) {
    buffer.setByte(payloadLength, value);
    return this;
  }

  @Incubating
  public int securityParameterIndex() {
    return buffer.getInt(securityParameterIndex);
  }

  @Incubating
  public Authentication securityParameterIndex(int value) {
    buffer.setInt(securityParameterIndex, value);
    return this;
  }

  @Incubating
  public int sequenceNumber() {
    return buffer.getInt(sequenceNumber);
  }

  @Incubating
  public Authentication sequenceNumber(int value) {
    buffer.setInt(sequenceNumber, value);
    return this;
  }

  @Incubating
  public byte[] integrityCheckValue() {
    byte[] bytes = new byte[(payloadLength() + 2) * 4 - 12];
    buffer.getBytes(integrityCheckValue, bytes);
    return bytes;
  }

  @Incubating
  public Authentication integrityCheckValue(byte[] value) {
    buffer.setBytes(integrityCheckValue, value, 0, Math.min(value.length, maxIcv));
    return this;
  }

  @Override
  public int size() {
    if (maxIcv == 0) {
      Validate.notIllegalState(buffer.readableBytes() >= 8, "buffer size is not sufficient.");
    }
    return (payloadLength() + 2) * 4;
  }

  @Override
  public String toString() {
    return "Authentication{" +
            "nextHeader=" + nextHeader +
            ", payloadLength=" + payloadLength +
            ", securityParameterIndex=" + securityParameterIndex +
            ", sequenceNumber=" + sequenceNumber +
            ", integrityCheckValue=" + integrityCheckValue +
            '}';
  }
}
