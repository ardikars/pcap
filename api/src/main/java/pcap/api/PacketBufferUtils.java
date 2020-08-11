/** This code is licenced under the GPL version 2. */
package pcap.api;

import java.foreign.memory.Pointer;
import java.nio.ByteBuffer;
import pcap.api.internal.PcapPacketBuffer;
import pcap.common.annotation.Inclubating;
import pcap.common.memory.Memory;
import pcap.spi.PacketBuffer;

@Inclubating
public class PacketBufferUtils {

  public static PacketBuffer fromDirectByteBuffer(ByteBuffer bb) {
    Pointer<Byte> p = Pointer.fromByteBuffer(bb);
    if (!bb.isDirect()) {
      throw new IllegalArgumentException("Buffer must be direct buffer.");
    }
    return PcapPacketBuffer.fromReference(p, bb.capacity());
  }

  public static PacketBuffer fromMemory(Memory memory) {
    ByteBuffer bb = memory.buffer(ByteBuffer.class);
    if (!bb.isDirect()) {
      throw new IllegalArgumentException("Buffer must be direct buffer.");
    }
    Pointer<Byte> p = Pointer.fromByteBuffer(bb);
    return PcapPacketBuffer.fromReference(p, memory.capacity());
  }
}
