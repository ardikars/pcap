package pcap.common.memory;

import pcap.common.annotation.Inclubating;

/**
 * Indicate the buffer is sliced.
 *
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 */
@Inclubating
public interface Sliced {

  /**
   * Unslice buffer.
   *
   * @return returns unsliced {@link Memory} buffer.
   */
  Memory unslice();
}
