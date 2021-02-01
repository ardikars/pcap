/*
 * Copyright (c) 2020-2021 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.codec.ip.extension.ip6;

import pcap.codec.AbstractPacket;
import pcap.common.util.Strings;
import pcap.spi.PacketBuffer;
import pcap.spi.annotation.Incubating;

@Incubating
public final class Fragment extends AbstractPacket {

  private final long nextHeader;
  private final long fragmentOffset;
  private final long identification;

  private Fragment(PacketBuffer buffer) {
    super(buffer);
    this.nextHeader = offset;
    this.fragmentOffset = nextHeader + 1 + 1; // 1 bytes reserved
    this.identification = fragmentOffset + 1;
  }

  @Incubating
  public int nextHeader() {
    return buffer.getByte(nextHeader);
  }

  @Incubating
  public Fragment nextHeader(int value) {
    buffer.setByte(nextHeader, value);
    return this;
  }

  @Incubating
  public int fragmentOffset() {
    return (short) (buffer.getShort(fragmentOffset) >> 3 & 0x1FFF);
  }

  @Incubating
  public Fragment fragmentOffset(int value) {
    int sscratch = (value & 0x1FFF) << 3 | (more() ? 1 : 0);
    buffer.setShort(fragmentOffset, sscratch);
    return this;
  }

  @Incubating
  public boolean more() {
    return (buffer.getShort(fragmentOffset) & 0x1) == 1;
  }

  @Incubating
  public Fragment more(boolean value) {
    int sscratch = (fragmentOffset() & 0x1FFF) << 3 | (value ? 1 : 0);
    buffer.setShort(fragmentOffset, sscratch);
    return this;
  }

  @Incubating
  public int identification() {
    return buffer.getInt(identification);
  }

  @Incubating
  public Fragment identification(int value) {
    buffer.setInt(identification, value);
    return this;
  }

  @Override
  public int size() {
    return 8;
  }

  @Override
  public String toString() {
    return Strings.toStringBuilder(this)
        .add("nextHeader", nextHeader())
        .add("fragmentOffset", fragmentOffset())
        .add("identification", identification())
        .toString();
  }
}
