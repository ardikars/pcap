/** This code is licenced under the GPL version 2. */
package pcap.common.memory;

import pcap.common.annotation.Inclubating;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@Inclubating
class PooledMemory {

  private Memory memory;

  public PooledMemory(Memory referent) {
    this.memory = referent;
  }

  public Memory get() {
    return memory;
  }
}
