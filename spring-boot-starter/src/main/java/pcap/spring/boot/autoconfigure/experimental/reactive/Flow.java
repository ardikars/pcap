package pcap.spring.boot.autoconfigure.experimental.reactive;

import java.util.function.Function;
import org.reactivestreams.Publisher;
import pcap.spi.Pcap;
import pcap.spring.boot.autoconfigure.experimental.reactive.mapper.PacketMapper;
import pcap.spring.boot.autoconfigure.experimental.reactive.publisher.PacketPublisher;

public abstract class Flow<T> implements Publisher<T> {

  public <K> Flow<K> map(Function<T, K> function) {
    return new PacketMapper<T, K>(this, function);
  }

  public static <T> Flow<ReactivePacket<T>> from(Pcap pcap, T arguments) {
    Flow<ReactivePacket<T>> publisher = new PacketPublisher(pcap, arguments);
    return publisher;
  }
}
