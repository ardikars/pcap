/** This code is licenced under the GPL version 2. */
package pcap.common.memory;

import pcap.common.annotation.Inclubating;
import pcap.common.util.Validate;

/**
 * Polled memory wrapper.
 *
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 */
@Inclubating
public class PooledMemory {

  private Memory memory;

  public PooledMemory(Memory referent) {
    Validate.notIllegalArgument(referent instanceof Pooled, "Referent must be pooled memory.");
    this.memory = referent;
  }

  public Memory get() {
    return memory;
  }
}
