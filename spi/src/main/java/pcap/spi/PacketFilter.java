/*
 * Copyright (c) 2020-2023 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.spi;

import pcap.spi.annotation.Incubating;
import pcap.spi.util.Consumer;

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

  /**
   * Dump the compiled packet-matching code in a human readable form. Please mind that although code
   * compilation is always DLT-specific, typically it is impossible (and unnecessary) to specify
   * which DLT to use for the dump.
   *
   * @param consumer consumer.
   */
  @Incubating
  void dump(Consumer<String> consumer);
}
