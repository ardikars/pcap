package pcap.spring.boot.autoconfigure.experimental.event;

public interface EventHandler<T> {

  void onSuccess(T data);
}
