/** This code is licenced under the GPL version 2. */
package pcap.spring.boot.autoconfigure.handler;

import pcap.common.memory.Memory;
import pcap.spi.PacketHeader;

abstract class ThreadedRawEventLoop<T> extends EventLoop<T> implements PacketListener<T, Memory> {

  ThreadedRawEventLoop(int numberOfThread) {
    run(numberOfThread);
  }

  @Override
  public void onReceived(T args, PacketHeader header, Memory memory) {
    next(args, header, memory);
  }
}
