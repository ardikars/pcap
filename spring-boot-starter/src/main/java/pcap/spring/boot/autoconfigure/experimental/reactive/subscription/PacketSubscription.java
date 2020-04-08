/** This code is licenced under the GPL version 2. */
package pcap.spring.boot.autoconfigure.experimental.reactive.subscription;

import java.util.concurrent.atomic.AtomicLongFieldUpdater;
import org.reactivestreams.Subscriber;
import org.reactivestreams.Subscription;
import pcap.spi.PacketHandler;
import pcap.spi.Pcap;
import pcap.spi.exception.ErrorException;
import pcap.spi.exception.error.BreakException;
import pcap.spring.boot.autoconfigure.experimental.reactive.ReactivePacket;

public class PacketSubscription<T> implements Subscription {

  private final AtomicLongFieldUpdater<PacketSubscription> counterUpdater =
      AtomicLongFieldUpdater.newUpdater(PacketSubscription.class, "counter");

  private final Pcap pcap;
  private final PacketHandler<T> packetHandler;
  private final T arguments;
  private final Subscriber<ReactivePacket<T>> subscriber;
  private volatile long counter;
  private volatile boolean cancelled;

  public PacketSubscription(Pcap pcap, T arguments, Subscriber<ReactivePacket<T>> subscriber) {
    this.pcap = pcap;
    this.arguments = arguments;
    this.subscriber = subscriber;
    this.packetHandler =
        (args, header, buffer) -> {
          subscriber.onNext(new ReactivePacket<T>(header, buffer, args));
          counterUpdater.incrementAndGet(this);
        };
  }

  @Override
  public void request(long n) {
    if (!cancelled) {
      for (; ; ) {
        if (counter == n) {
          close();
          subscriber.onComplete();
          return;
        }
        try {
          pcap.dispatch(-1, packetHandler, arguments);
        } catch (BreakException e) {
          close();
          this.cancelled = true;
          subscriber.onError(e);
        } catch (ErrorException e) {
          close();
          subscriber.onError(e);
          return;
        }
      }
    }
  }

  @Override
  public void cancel() {
    pcap.breakLoop();
  }

  private void close() {
    pcap.close();
  }
}
