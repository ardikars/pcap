/** This code is licenced under the GPL version 2. */
package pcap.spring.boot.autoconfigure.handler;

public abstract class MultiThreadPacketEventLoop<T> extends ThreadedPacketEventLoop<T> {

  public MultiThreadPacketEventLoop() {
    super(Runtime.getRuntime().availableProcessors());
  }
}
