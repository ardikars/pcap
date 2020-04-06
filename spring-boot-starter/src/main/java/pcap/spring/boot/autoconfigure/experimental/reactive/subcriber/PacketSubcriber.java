package pcap.spring.boot.autoconfigure.experimental.reactive.subcriber;

import org.reactivestreams.Subscriber;
import org.reactivestreams.Subscription;

public abstract class PacketSubcriber<T> implements Subscriber<T> {

  private final int count;

  public PacketSubcriber() {
    this.count = -1;
  }

  public PacketSubcriber(int count) {
    this.count = count;
  }

  @Override
  public void onSubscribe(Subscription subscription) {
    subscription.request(count);
  }

  @Override
  public void onNext(T t) {}

  @Override
  public void onError(Throwable throwable) {}

  @Override
  public void onComplete() {}
}
