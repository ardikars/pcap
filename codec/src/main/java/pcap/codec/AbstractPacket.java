/** This code is licenced under the GPL version 2. */
package pcap.codec;

import java.io.Serializable;
import java.util.*;
import java.util.function.Consumer;
import java.util.function.Function;
import pcap.common.annotation.Inclubating;
import pcap.common.memory.Memory;
import pcap.common.memory.MemoryAllocator;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@Inclubating
public abstract class AbstractPacket implements Packet {

  protected static final String ILLEGAL_HEADER_EXCEPTION = "Missing required header field(s).";

  protected Memory payloadBuffer;

  /**
   * Returns the {@link Memory} object representing this packet's payload.
   *
   * @return returns empty buffer if a payload doesn't exits, {@link Memory} object otherwise.
   */
  public Memory payloadBuffer() {
    if (payloadBuffer == null) {
      payloadBuffer = Properties.BYTE_BUF_ALLOCATOR.allocate(0);
    }
    return payloadBuffer;
  }

  @Override
  public <T extends Packet> boolean contains(Class<T> clazz) {
    return !get(clazz).isEmpty();
  }

  @Override
  public <T extends Packet> List<T> get(Class<T> clazz) {
    List<Packet> packets = new ArrayList<>();
    Iterator<Packet> iterator = this.iterator();
    while (iterator.hasNext()) {
      Packet packet = iterator.next();
      if (clazz.isInstance(packet)) {
        packets.add(packet);
      }
    }
    return (List<T>) packets;
  }

  @Override
  public <T extends Packet> T getFirst(Class<T> clazz) {
    final PacketIterator iterator = this.iterator();
    while (iterator.hasNext()) {
      Packet packet = iterator.next();
      if (packet.getClass().isAssignableFrom(clazz)) {
        return (T) packet;
      }
    }
    return null;
  }

  @Override
  public <T extends Packet> T getLast(Class<T> clazz) {
    Iterator<Packet> iterator = this.iterator();
    Packet packet = null;
    while (iterator.hasNext()) {
      packet = iterator.next();
      if (packet.getClass().isAssignableFrom(clazz)) {
        return (T) packet;
      }
    }
    return (T) packet;
  }

  @Override
  public PacketIterator iterator() {
    return new PacketIterator(this);
  }

  @Override
  public void forEach(Consumer<? super Packet> action) throws NullPointerException {
    PacketIterator iterator = iterator();
    while (iterator.hasNext()) {
      try {
        action.accept(iterator.next());
      } catch (Exception e) {
        // do nothing
      }
    }
  }

  public abstract Builder builder();

  public abstract Memory buffer();

  public abstract static class Header implements Packet.Header {

    protected static final MemoryAllocator ALLOCATOR = Properties.BYTE_BUF_ALLOCATOR;

    protected Memory buffer;

    /**
     * Get reminder of buffer.
     *
     * @param buffer buffer.
     * @param length lenght.
     * @return returns {@link Memory}.
     */
    protected Memory slice(Memory buffer, int length) {
      if (buffer == null) {
        return null;
      }
      if (buffer.readableBytes() <= length && buffer.readerIndex() - length > 0) {
        return buffer.slice(buffer.readerIndex() - length, length);
      } else {
        return buffer.slice();
      }
    }

    /**
     * Returns header as byte buffer.
     *
     * @return return byte buffer.
     */
    public Memory buffer() {
      if (buffer == null) {
        buffer = ALLOCATOR.allocate(0);
      }
      return buffer;
    }

    public abstract Builder builder();
  }

  public <T extends Packet, R extends Packet> R map(Function<T, R> function) {
    return function.apply((T) this);
  }

  public <T extends Packet> List<T> collectList() {
    List<T> list = new ArrayList<>();
    PacketIterator iterator = iterator();
    while (iterator.hasNext()) {
      list.add((T) iterator.next());
    }
    return list;
  }

  public <T extends Packet> Set<T> collectSet() {
    Set<T> set = new HashSet<>();
    PacketIterator iterator = iterator();
    while (iterator.hasNext()) {
      set.add((T) iterator.next());
    }
    return set;
  }

  /** Packet builder. */
  public abstract static class Builder
      implements pcap.common.util.Builder<Packet, Memory>, Serializable {

    protected int readerIndex = -1;
    protected int writerIndex = -1;

    protected void resetIndex(Memory buffer) {
      if (readerIndex < 0 || writerIndex < 0) {
        this.readerIndex = buffer.readerIndex();
        this.writerIndex = buffer.writerIndex();
      } else {
        buffer.setIndex(readerIndex, buffer.capacity());
      }
    }

    public Builder reset() {
      return reset(-1, -1);
    }

    public Builder reset(int offset, int length) {
      return this;
    }
  }

  /** Packet factory. */
  public abstract static class Factory implements pcap.common.util.Factory<Packet, Memory> {}
}
