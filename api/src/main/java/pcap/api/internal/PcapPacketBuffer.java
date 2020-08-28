/** This code is licenced under the GPL version 2. */
package pcap.api.internal;

import java.foreign.memory.Pointer;
import java.nio.ByteBuffer;
import pcap.common.annotation.Inclubating;
import pcap.common.memory.internal.nio.DirectByteBuffer;
import pcap.spi.PacketBuffer;

/**
 * Wrapper for {@code pcap} packet buffer.
 *
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 */
@Inclubating
public class PcapPacketBuffer extends DirectByteBuffer implements PacketBuffer {

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
  public PcapPacketBuffer readerIndex(long readerIndex) {
    super.readerIndex(readerIndex);
    return this;
  }

  @Override
  public PcapPacketBuffer writerIndex(long writerIndex) {
    super.writerIndex(writerIndex);
    return this;
  }

  @Override
  public PcapPacketBuffer copy(long index, long length) {
    int capacity = buffer.capacity();
    ByteBuffer newBuffer = ByteBuffer.allocateDirect(capacity);
    Pointer<Byte> newRef = Pointer.fromByteBuffer(newBuffer);
    Pointer.copy(ref, newRef);
    return PcapPacketBuffer.fromReference(newRef, capacity);
  }

  @Override
  public Sliced slice(long index, long length) {
    if (length > capacity - index) {
      throw new IllegalArgumentException(
          String.format("length: %d (expected: length <= %d)", length, capacity - index));
    }
    return new Sliced((int) index & 0x7FFFFFFF, (int) length & 0x7FFFFFFF, this);
  }

  @Override
  public PcapPacketBuffer duplicate() {
    return new PcapPacketBuffer(
        ptr,
        ref,
        baseIndex,
        buffer.duplicate(),
        (int) capacity(),
        (int) maxCapacity(),
        (int) readerIndex(),
        (int) writerIndex());
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
          previous.maxCapacity() - index < 0 ? 0 : (int) previous.maxCapacity() - index,
          previous.readerIndex() - index < 0 ? 0 : (int) previous.readerIndex() - index,
          previous.writerIndex() - index < 0 ? 0 : (int) previous.writerIndex() - index);
      this.previous = previous;
    }
  }
}
