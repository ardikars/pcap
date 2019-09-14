/** This code is licenced under the GPL version 2. */
package pcap.common.util;

import pcap.common.annotation.Inclubating;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@Inclubating
public interface Builder<T, V> {

  /**
   * Build object.
   *
   * @return object.
   */
  T build();

  /**
   * Build object with given argument.
   *
   * @param value value.
   * @return object.
   */
  T build(V value);
}
