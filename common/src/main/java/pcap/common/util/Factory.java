/** This code is licenced under the GPL version 2. */
package pcap.common.util;

import pcap.common.annotation.Inclubating;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@Inclubating
public interface Factory<T, V> {

  /**
   * Build object.
   *
   * @param value param.
   * @return object.
   */
  T newInstance(V value);
}
