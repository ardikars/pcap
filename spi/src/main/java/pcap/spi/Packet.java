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

    protected final PacketBuffer buffer;
    protected final long offset;
    protected final long length;

    /**
     * A class that extends this abstract class must have constructor with single {@link
     * PacketBuffer} parameter.
     *
     * @param buffer packet buffer.
     * @since 1.0.0
     */
    protected Abstract(PacketBuffer buffer) {
      this.buffer = buffer;
      if (buffer.readableBytes() < size()) {
        throw new IllegalArgumentException(
            String.format(
                "buffer.readableBytes: %d (expected: buffer.readableBytes(%d) >= packet.size(%d))",
                buffer.readableBytes(), buffer.readableBytes(), size()));
      }
      this.offset = buffer.readerIndex();
      this.length = size();
    }

    /** {@inheritDoc} */
    @Override
    public PacketBuffer buffer() {
      return buffer;
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
        if (buffer.getByte(offset + i) != packet.buffer.getByte(packet.offset + i)) {
          return false;
        }
      }
      return true;
    }

    @Override
    public int hashCode() {
      int result = 1;
      long length = offset + size();
      for (long i = offset; i < length; i++) {
        result = 31 * result + buffer.getByte(i);
      }
      return result;
    }
  }
}
