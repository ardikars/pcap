/*
 * Copyright (c) 2020-2021 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.codec.loopback;

import pcap.codec.AbstractPacket;
import pcap.common.util.Strings;
import pcap.common.util.Validate;
import pcap.spi.PacketBuffer;
import pcap.spi.annotation.Incubating;

/**
 * Null/Loopback
 *
 * @since 1.3.0
 */
@Incubating
public class Loopback extends AbstractPacket {

  private final long family;

  private Loopback(PacketBuffer buffer) {
    super(buffer);
    this.family = offset;
  }

  /**
   * Wrap buffer into {@link Loopback}.
   *
   * @param size {@link Loopback} header size.
   * @param buffer buffer.
   * @return returns {@link Loopback} instance.
   * @since 1.3.0
   */
  @Incubating
  public static Loopback newInstance(int size, PacketBuffer buffer) {
    Validate.notIllegalArgument(
        size == 4 && buffer.readableBytes() >= 4, "buffer size is not sufficient.");
    return new Loopback(buffer);
  }

  /**
   * Get protocol family.
   *
   * @return returns protocol family.
   * @since 1.3.0
   */
  @Incubating
  public int family() {
    return buffer.getInt(family);
  }

  /**
   * Set protocol family.
   *
   * @param value protocol family.
   * @return returns this instance.
   * @since 1.3.0
   */
  @Incubating
  public Loopback family(int value) {
    buffer.setInt(family, value);
    return this;
  }

  /** {@inheritDoc} */
  @Override
  protected int size() {
    return 4;
  }

  @Override
  public String toString() {
    return Strings.toStringBuilder(this).add("family", family()).toString();
  }
}
