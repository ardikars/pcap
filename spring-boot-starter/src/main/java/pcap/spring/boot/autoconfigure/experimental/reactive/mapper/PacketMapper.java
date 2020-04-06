package pcap.spring.boot.autoconfigure.experimental.reactive.mapper;

import java.util.Objects;
import java.util.function.Function;
import org.reactivestreams.Publisher;
import org.reactivestreams.Subscriber;
import org.reactivestreams.Subscription;
import pcap.spring.boot.autoconfigure.experimental.reactive.Flow;

public class PacketMapper<IN, OUT> extends Flow<OUT> {

  private final Publisher<IN> parent;
  private final Function<IN, OUT> mapper;

  public PacketMapper(Publisher<IN> parent, Function<IN, OUT> mapper) {
    this.parent = parent;
    this.mapper = mapper;
  }

  @Override
  public void subscribe(Subscriber<? super OUT> subscriber) {
    parent.subscribe(new Mapper(mapper, subscriber));
  }

  public static class Mapper<IN, OUT> implements Subscriber<IN>, Subscription {

    private final Function<IN, OUT> mapper;
    private final Subscriber<OUT> actual;
    private Subscription upstrem;
    private boolean terminated;

    public Mapper(Function<IN, OUT> mapper, Subscriber<OUT> actual) {
      this.mapper = mapper;
      this.actual = actual;
    }

    @Override
    public void onSubscribe(Subscription subscription) {
      this.upstrem = subscription;
      actual.onSubscribe(this);
    }

    @Override
    public void onNext(IN in) {
      if (terminated) {
        return;
      }
      OUT out;
      try {
        out = Objects.requireNonNull(mapper.apply(in));
      } catch (Throwable throwable) {
        cancel();
        onError(throwable);
        return;
      }
      actual.onNext(out);
    }

    @Override
    public void onError(Throwable throwable) {
      if (terminated) {
        return;
      }
      terminated = true;
      actual.onError(throwable);
    }

    @Override
    public void onComplete() {
      if (terminated) {
        return;
      }
      terminated = true;
      actual.onComplete();
    }

    @Override
    public void request(long n) {
      upstrem.request(n);
    }

    @Override
    public void cancel() {
      upstrem.cancel();
    }
  }
}
