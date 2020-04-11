package pcap.spring.boot.autoconfigure.experimental.event;

import java.util.ArrayList;
import java.util.List;
import java.util.Queue;
import java.util.concurrent.LinkedBlockingQueue;
import pcap.codec.Packet;
import pcap.codec.ethernet.Ethernet;
import pcap.common.memory.Memory;
import pcap.spring.boot.autoconfigure.experimental.reactive.Flow;
import pcap.spring.boot.autoconfigure.experimental.reactive.publisher.PacketPublisher;

public class EventLoop {

  private final Queue<Memory> queue = new LinkedBlockingQueue<>();
  private final List<EventHandler<?>> eventHandlers = new ArrayList<>();

  public boolean offer(Memory memory) {
    return queue.offer(memory);
  }

  public <T> boolean addEventHandler(EventHandler<T> eventHandler) {
    return eventHandlers.add(eventHandler);
  }

  public void loop() {
    for (; ; ) {
      for (EventHandler eventHandler : eventHandlers) {
        if (eventHandler instanceof PacketEventHandler) {
          Memory memory = queue.poll();
          memory.writerIndex(memory.capacity());
          Packet packet = Ethernet.newPacket(memory);
          eventHandler.onSuccess(packet);
        } else if (eventHandler instanceof ReativePacketEventHandler) {
          Flow<String> flow = new PacketPublisher<>(null, "");
          eventHandler.onSuccess(flow);
        }
      }
    }
  }
}
