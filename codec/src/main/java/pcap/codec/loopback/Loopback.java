/*
 * Copyright (c) 2020-2021 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.codec.loopback;

import java.util.Objects;
import pcap.codec.AbstractPacket;
import pcap.common.util.Strings;
import pcap.common.util.Validate;
import pcap.spi.PacketBuffer;
import pcap.spi.annotation.Incubating;

/**
 * Null/Loopback
 *
 * @since 1.3.0 (incubating)
 */
@Incubating
public final class Loopback extends AbstractPacket {

  public static final int TYPE = 0;

  private final long familyOffset;

  private Loopback(PacketBuffer buffer) {
    super(buffer);
    this.familyOffset = superOffset;
  }

  /**
   * Wrap buffer into {@link Loopback}.
   *
   * @param size {@link Loopback} header size.
   * @param buffer buffer.
   * @return returns {@link Loopback} instance.
   * @since 1.3.0 (incubating)
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
   * @since 1.3.0 (incubating)
   */
  @Incubating
  public int family() {
    return superBuffer.getInt(familyOffset);
  }

  /**
   * Set protocol family.
   *
   * @param value protocol family.
   * @return returns this instance.
   * @since 1.3.0 (incubating)
   */
  @Incubating
  public Loopback family(int value) {
    superBuffer.setInt(familyOffset, value);
    return this;
  }

  /** {@inheritDoc} */
  @Override
  protected int size() {
    return 4;
  }

  @Override
  public boolean equals(Object o) {
    return super.equals(o);
  }

  @Override
  public int hashCode() {
    return Objects.hash(super.hashCode(), family());
  }

  @Override
  public String toString() {
    return Strings.toStringBuilder(this).add("family", family()).toString();
  }
}
