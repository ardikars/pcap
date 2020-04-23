/** This code is licenced under the GPL version 2. */
package pcap.api.internal;

import pcap.common.annotation.Inclubating;
import pcap.spi.PacketBuffer;

import java.foreign.memory.Pointer;
import java.nio.ByteBuffer;

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

  private PcapPacketBuffer(Pointer<Pointer<Byte>> ptr, Pointer<Byte> ref, ByteBuffer buffer) {
    this.ptr = ptr;
    this.ref = ref;
    this.buffer = buffer;
  }

  public static PcapPacketBuffer fromPointer(Pointer<Pointer<Byte>> pointer, int size) {
    ByteBuffer buffer = pointer.get().asDirectByteBuffer(size);
    return new PcapPacketBuffer(pointer, pointer.get(), buffer);
  }

  public static PcapPacketBuffer fromReference(Pointer<Byte> reference, int size) {
    ByteBuffer buffer = reference.asDirectByteBuffer(size);
    return new PcapPacketBuffer(null, reference, buffer);
  }

  @Override
  public ByteBuffer buffer() {
    return buffer;
  }
}
