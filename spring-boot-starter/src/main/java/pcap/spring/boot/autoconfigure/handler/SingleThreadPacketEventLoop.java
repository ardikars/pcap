/** This code is licenced under the GPL version 2. */
package pcap.spring.boot.autoconfigure.handler;

public abstract class SingleThreadPacketEventLoop<T> extends ThreadedPacketEventLoop<T> {

  public SingleThreadPacketEventLoop() {
    super(1);
  }
}
