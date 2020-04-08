/** This code is licenced under the GPL version 2. */
package pcap.spring.boot.autoconfigure.experimental.reactive.publisher;

import org.reactivestreams.Subscriber;
import pcap.spi.Pcap;
import pcap.spring.boot.autoconfigure.experimental.reactive.Flow;
import pcap.spring.boot.autoconfigure.experimental.reactive.subscription.PacketSubscription;

public class PacketPublisher<T> extends Flow<T> {

  private final Pcap pcap;
  private final T arguments;
  private volatile boolean subcribed;

  public PacketPublisher(Pcap pcap, T arguments) {
    this.pcap = pcap;
    this.arguments = arguments;
  }

  @Override
  public void subscribe(Subscriber<? super T> subscriber) {
    if (subcribed) {
      subscriber.onError(new IllegalStateException("Multiple subscriber doesn't supported"));
    }
    subscriber.onSubscribe(new PacketSubscription(pcap, arguments, subscriber));
    this.subcribed = true;
  }
}
