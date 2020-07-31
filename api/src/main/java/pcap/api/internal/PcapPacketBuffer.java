/** This code is licenced under the GPL version 2. */
package pcap.api.internal;

import java.foreign.memory.Pointer;
import java.nio.ByteBuffer;
import pcap.common.annotation.Inclubating;
import pcap.common.memory.Memory;
import pcap.common.memory.internal.nio.AbstractByteBuffer;
import pcap.spi.PacketBuffer;

/**
 * Wrapper for {@code pcap} packet buffer.
 *
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 */
@Inclubating
public class PcapPacketBuffer extends AbstractByteBuffer
    implements PacketBuffer, Memory.Direct<Long> {

  final Pointer<Pointer<Byte>> ptr; // nullable
  final Pointer<Byte> ref;
  final int capacity;

  private PcapPacketBuffer(
      Pointer<Pointer<Byte>> ptr,
      Pointer<Byte> ref,
      int baseIndex,
      ByteBuffer buffer,
      int capacity,
      int maxCapacity,
      int readerIndex,
      int writerIndex) {
    super(baseIndex, buffer, capacity, maxCapacity, readerIndex, writerIndex);
    this.ptr = ptr;
    this.ref = ref;
    this.buffer = buffer;
    this.capacity = capacity;
  }

  public static PcapPacketBuffer fromPointer(Pointer<Pointer<Byte>> pointer, int size) {
    ByteBuffer buffer = pointer.get().asDirectByteBuffer(size);
    return new PcapPacketBuffer(pointer, pointer.get(), 0, buffer, size, size, 0, 0);
  }

  public static PcapPacketBuffer fromReference(Pointer<Byte> reference, int size) {
    ByteBuffer buffer = reference.asDirectByteBuffer(size);
    return new PcapPacketBuffer(null, reference, 0, buffer, size, size, 0, 0);
  }

  @Override
  public PcapPacketBuffer readerIndex(int readerIndex) {
    super.readerIndex(readerIndex);
    return this;
  }

  @Override
  public PcapPacketBuffer writerIndex(int writerIndex) {
    super.writerIndex(writerIndex);
    return this;
  }

  @Deprecated
  @Override
  public ByteBuffer buffer() {
    return nioBuffer();
  }

  @Override
  public int capacity() {
    return capacity;
  }

  @Override
  public Memory copy(int index, int length) {
    int capacity = buffer.capacity();
    ByteBuffer newBuffer = ByteBuffer.allocateDirect(capacity);
    Pointer<Byte> newRef = Pointer.fromByteBuffer(newBuffer);
    Pointer.copy(ref, newRef);
    return PcapPacketBuffer.fromReference(newRef, capacity);
  }

  @Override
  public Memory slice(int index, int length) {
    if (length > capacity - index) {
      throw new IllegalArgumentException(
          String.format("length: %d (expected: length <= %d)", length, capacity - index));
    }
    return new Sliced(index, length, this);
  }

  @Override
  public Memory duplicate() {
    return new PcapPacketBuffer(
        ptr,
        ref,
        baseIndex,
        buffer.duplicate(),
        capacity(),
        maxCapacity(),
        readerIndex(),
        writerIndex());
  }

  @Override
  public Long memoryAddress() {
    return ptr == null ? ref.addr() : ptr.get().addr();
  }

  @Override
  public long address() {
    return memoryAddress();
  }

  public static final class Sliced extends PcapPacketBuffer {

    final PcapPacketBuffer previous;

    public Sliced(int index, int length, PcapPacketBuffer previous) {
      super(
          previous.ptr,
          previous.ref,
          previous.baseIndex + index,
          previous.buffer(ByteBuffer.class).duplicate(),
          length,
          previous.maxCapacity() - index < 0 ? 0 : previous.maxCapacity() - index,
          previous.readerIndex() - index < 0 ? 0 : previous.readerIndex() - index,
          previous.writerIndex() - index < 0 ? 0 : previous.writerIndex() - index);
      this.previous = previous;
    }
  }
}
