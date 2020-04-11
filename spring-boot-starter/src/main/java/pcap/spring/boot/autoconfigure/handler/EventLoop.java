/** This code is licenced under the GPL version 2. */
package pcap.spring.boot.autoconfigure.handler;

import java.util.Objects;
import java.util.Queue;
import java.util.concurrent.*;
import pcap.common.memory.Memories;
import pcap.common.memory.Memory;
import pcap.spi.PacketBuffer;
import pcap.spi.PacketHandler;
import pcap.spi.PacketHeader;

/**
 * Packet event loop
 *
 * @param <T> args type
 */
abstract class EventLoop<T> implements PacketHandler<T> {

  private final Queue<DataWrapper> queue = new LinkedBlockingQueue<>();

  @Override
  public void gotPacket(T args, PacketHeader header, PacketBuffer buffer) {
    Memory memory = Memories.wrap(buffer.buffer());
    memory.writerIndex(header.length());
    DataWrapper<T> dataWrapper = new DataWrapper<>(memory, header, args);
    queue.offer(dataWrapper);
  }

  public abstract void onReceived(T args, PacketHeader header, Memory memory);

  private static class DataWrapper<T> {

    private Memory memory;
    private PacketHeader header;
    private T args;

    public DataWrapper(Memory memory, PacketHeader header, T args) {
      this.memory = memory;
      this.header = header;
      this.args = args;
    }

    @Override
    public boolean equals(Object o) {
      if (this == o) return true;
      if (o == null || getClass() != o.getClass()) return false;
      DataWrapper<?> that = (DataWrapper<?>) o;
      return Objects.equals(memory, that.memory)
          && Objects.equals(header, that.header)
          && Objects.equals(args, that.args);
    }

    @Override
    public int hashCode() {
      return Objects.hash(memory, header, args);
    }
  }

  protected void run(int numberOfThread) {
    Executor executor;
    if (numberOfThread == 1) {
      executor = Executors.newSingleThreadExecutor();
    } else {
      executor = Executors.newFixedThreadPool(numberOfThread);
    }
    Runnable runnable =
        () -> {
          for (; ; ) {
            DataWrapper<T> dataWrapper = queue.poll();
            if (dataWrapper != null) {
              Memory memory = dataWrapper.memory;
              PacketHeader header = dataWrapper.header;
              T args = dataWrapper.args;
              onReceived(args, header, memory);
            }
          }
        };
    executor.execute(runnable);
  }
}
