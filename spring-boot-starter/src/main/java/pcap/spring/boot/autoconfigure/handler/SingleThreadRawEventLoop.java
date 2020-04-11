/** This code is licenced under the GPL version 2. */
package pcap.spring.boot.autoconfigure.handler;

public abstract class SingleThreadRawEventLoop<T> extends ThreadedRawEventLoop<T> {

  public SingleThreadRawEventLoop() {
    super(1);
  }
}
