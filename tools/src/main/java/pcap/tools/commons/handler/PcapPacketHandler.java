package pcap.tools.commons.handler;

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
    Memory memory = Memories.wrap(buffer.buffer());
    memory.writerIndex(memory.capacity());
    Packet packet = Ethernet.newPacket(memory);
    gotPacket(args, header, packet);
  }

  void gotPacket(T args, PacketHeader header, Packet buffer);
}
