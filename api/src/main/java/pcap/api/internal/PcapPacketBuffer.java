/** This code is licenced under the GPL version 2. */
package pcap.api.internal;

import java.foreign.memory.Pointer;
import java.nio.ByteBuffer;
import pcap.common.annotation.Inclubating;
import pcap.spi.PacketBuffer;

/**
 * Wrapper for {@code pcap} packet buffer.
 *
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 */
@Inclubating
public class PcapPacketBuffer implements PacketBuffer {

  Pointer<Pointer<Byte>> ptr;
  Pointer<Byte> ref;
  ByteBuffer buffer;
  long capacity;

  private PcapPacketBuffer(
      Pointer<Pointer<Byte>> ptr, Pointer<Byte> ref, ByteBuffer buffer, long capacity) {
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
  public ByteBuffer buffer() {
    return buffer;
  }

  @Override
  public long capacity() {
    return capacity;
  }
}
