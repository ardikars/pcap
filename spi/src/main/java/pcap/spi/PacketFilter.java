/*
 * Copyright (c) 2020-2023 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.spi;

/**
 * Packet filter.
 *
 * @since 1.5.0
 */
public interface PacketFilter extends AutoCloseable {

  /**
   * Filter packet buffer.
   *
   * @param packetBuffer packet buffer.
   * @return returns {@code true} if filtered, {@code false} otherwise.
   * @since 1.5.0
   */
  boolean filter(PacketBuffer packetBuffer);
}
