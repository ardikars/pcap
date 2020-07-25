/** This code is licenced under the GPL version 2. */
package pcap.api.internal;

import java.foreign.memory.Pointer;
import java.nio.ByteBuffer;
import pcap.common.annotation.Inclubating;
import pcap.common.memory.Memory;
import pcap.common.memory.internal.nio.AbstractByteBuffer;
import pcap.common.memory.internal.nio.DirectByteBuffer;
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
      Pointer<Pointer<Byte>> ptr, Pointer<Byte> ref, ByteBuffer buffer, int capacity) {
    super(0, buffer, capacity, capacity, 0, 0);
    this.ptr = ptr;
    this.ref = ref;
    this.buffer = buffer;
    this.capacity = capacity;
  }

  public static PcapPacketBuffer fromPointer(Pointer<Pointer<Byte>> pointer, int size) {
    ByteBuffer buffer = pointer.get().asDirectByteBuffer(size);
    return new PcapPacketBuffer(pointer, pointer.get(), buffer, size);
  }

  public static PcapPacketBuffer fromReference(Pointer<Byte> reference, int size) {
    ByteBuffer buffer = reference.asDirectByteBuffer(size);
    return new PcapPacketBuffer(null, reference, buffer, size);
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
    DirectByteBuffer directByteBuffer =
        new DirectByteBuffer(
            0, nioBuffer(), capacity(), maxCapacity(), readerIndex(), writerIndex());
    return directByteBuffer.slice(index, length);
  }

  @Override
  public Memory duplicate() {
    return ptr == null
        ? PcapPacketBuffer.fromReference(ref, capacity())
        : PcapPacketBuffer.fromPointer(ptr, capacity());
  }

  @Override
  public Long memoryAddress() {
    return ptr == null ? ref.addr() : ptr.get().addr();
  }

  @Override
  public long address() {
    return memoryAddress();
  }
}
