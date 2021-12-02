/*
 * Copyright (c) 2020-2021 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.spi;

/**
 * Used by {@link PacketBuffer#cast(Class)}.
 *
 * @since 1.0.0
 */
public interface Packet {

  /**
   * Get packet buffer.
   *
   * @return returns packet buffer.
   * @since 1.0.0
   */
  PacketBuffer buffer();

  /**
   * Abstract packet.
   *
   * @since 1.0.0
   */
  abstract class Abstract implements Packet {

    protected final PacketBuffer superBuffer;
    protected final long superOffset;
    protected final long superLength;

    /**
     * A class that extends this abstract class must have constructor with single {@link
     * PacketBuffer} parameter.
     *
     * @param buffer packet buffer.
     * @since 1.0.0
     */
    protected Abstract(PacketBuffer buffer) {
      this.superBuffer = buffer;
      if (buffer.readableBytes() < size()) {
        throw new IllegalArgumentException(
            String.format(
                "buffer.readableBytes: %d (expected: buffer.readableBytes(%d) >= packet.size(%d))",
                buffer.readableBytes(), buffer.readableBytes(), size()));
      }
      this.superOffset = buffer.readerIndex();
      this.superLength = size();
    }

    /** {@inheritDoc} */
    @Override
    public PacketBuffer buffer() {
      return superBuffer;
    }

    /**
     * Get packet size.
     *
     * @return returns packet size.
     * @since 1.0.0
     */
    protected abstract int size();

    @Override
    public boolean equals(Object o) {
      if (!(o instanceof Abstract)) {
        return false;
      }
      Abstract packet = (Abstract) o;
      if (size() != packet.size()) {
        return false;
      }
      int size = size();
      for (long i = 0; i < size; i++) {
        if (superBuffer.getByte(superOffset + i)
            != packet.superBuffer.getByte(packet.superOffset + i)) {
          return false;
        }
      }
      return true;
    }

    @Override
    public int hashCode() {
      int result = 1;
      long len = superOffset + size();
      for (long i = superOffset; i < len; i++) {
        result = 31 * result + superBuffer.getByte(i);
      }
      return result;
    }
  }
}
