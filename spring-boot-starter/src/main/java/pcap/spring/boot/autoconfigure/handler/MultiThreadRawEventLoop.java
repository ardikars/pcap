/** This code is licenced under the GPL version 2. */
package pcap.spring.boot.autoconfigure.handler;

public abstract class MultiThreadRawEventLoop<T> extends ThreadedRawEventLoop<T> {

  public MultiThreadRawEventLoop() {
    super(Runtime.getRuntime().availableProcessors());
  }
}
