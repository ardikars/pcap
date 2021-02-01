/*
 * Copyright (c) 2020-2021 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.codec.ip.extension.ip6;

import pcap.spi.PacketBuffer;
import pcap.spi.annotation.Incubating;

/** https://tools.ietf.org/html/rfc2460 */
@Incubating
public final class HopByHopOptions extends Option.Header {

  private HopByHopOptions(PacketBuffer buffer) {
    super(buffer);
  }

  @Override
  public String toString() {
    return super.toString();
  }
}
