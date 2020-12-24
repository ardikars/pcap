/*
 * Copyright (c) 2020 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.spi;

/**
 * A callback function used to handle {@link Pcap#loop(int, PacketHandler, Object)} and {@link
 * Pcap#dispatch(int, PacketHandler, Object)}.
 *
 * @since 1.0.0
 */
public interface PacketHandler<T> {

  /**
   * Callback specifies a {@code PacketHandler} routine to be called with three arguments : a {@code
   * args} which is passed in the user argument to {@code Pcap#loop()} or {@code Pcap#dispatch()}, a
   * {@link PacketHeader} pointer pointing to the packet time stamp and lengths, and a {@code args}
   * to the first caplen bytes of data from the packet.
   *
   * <p>Note: {@link PacketHeader} and the {@link PacketBuffer} are not to be freed by the callback
   * routine, and are not guaranteed to be valid after the callback routine returns; if the code
   * needs them to be valid after the callback, it must make a copy of them.
   *
   * @param args attachments.
   * @param header packet timestamp and length.
   * @param buffer buffer.
   * @since 1.0.0
   */
  void gotPacket(T args, PacketHeader header, PacketBuffer buffer);
}
