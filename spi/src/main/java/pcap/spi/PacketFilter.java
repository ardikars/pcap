/*
 * Copyright (c) 2020-2021 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.spi;

/** Packet filter. */
public interface PacketFilter extends AutoCloseable {

  /**
   * Filter packet buffer.
   *
   * @param packetBuffer packet buffer.
   * @param packetLength packet original length.
   * @return returns {@code true} if filtered, {@code false} otherwise.
   */
  boolean filter(PacketBuffer packetBuffer, long packetLength);
}
