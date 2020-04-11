/** This code is licenced under the GPL version 2. */
package pcap.spring.boot.autoconfigure.handler;

import pcap.codec.Packet;
import pcap.codec.ethernet.Ethernet;
import pcap.common.memory.Memory;
import pcap.spi.PacketHeader;

abstract class ThreadedPacketEventLoop<T> extends EventLoop<T>
    implements PacketListener<T, Packet> {

  ThreadedPacketEventLoop(int numberOfThread) {
    run(numberOfThread);
  }

  @Override
  public void onReceived(T args, PacketHeader header, Memory memory) {
    Packet packet = Ethernet.newPacket(memory);
    next(args, header, packet);
  }
}
