package pcap.spring.boot.autoconfigure.handler;

import java.nio.ByteBuffer;
import pcap.api.handler.EventLoopHandler;
import pcap.codec.Packet;
import pcap.codec.ethernet.Ethernet;
import pcap.common.memory.Memories;
import pcap.common.memory.Memory;
import pcap.spi.PacketBuffer;
import pcap.spi.PacketHeader;

public interface PcapPacketHandler<T> extends EventLoopHandler<T> {

  @Override
  default void gotPacket(T args, PacketHeader header, PacketBuffer buffer) {
    ByteBuffer byteBuffer = buffer.buffer();
    Memory memory = Memories.wrap(byteBuffer);
    memory.writerIndex(memory.capacity());
    Packet packet = Ethernet.newPacket(memory);
    gotPacket(args, header, packet);
  }

  void gotPacket(T args, PacketHeader header, Packet packet);
}
