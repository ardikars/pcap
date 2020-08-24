/** This code is licenced under the GPL version 2. */
package pcap.common.util;

import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.Set;
import pcap.common.annotation.Inclubating;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@Inclubating
public final class Sets {

  private static final float HASHSET_DEFAULT_LOAD_FACTOR = 0.75f;

  private Sets() {
    //
  }

  /**
   * Create an {@link HashSet} with its initialCapacity calculated to minimize rehash operations
   *
   * @param expectedMapSize expected map size
   * @param <E> type.
   * @return returns {@link Set} object.
   */
  public static <E> Set<E> createHashSet(int expectedMapSize) {
    final int initialCapacity = (int) (expectedMapSize / HASHSET_DEFAULT_LOAD_FACTOR) + 1;
    return new HashSet<>(initialCapacity, HASHSET_DEFAULT_LOAD_FACTOR);
  }

  /**
   * Create an {@link LinkedHashSet} with its initialCapacity calculated to minimize rehash
   * operations
   *
   * @param expectedMapSize expected map size
   * @param <E> type.
   * @return returns {@link Set} object.
   */
  public static <E> Set<E> createLinkedHashSet(int expectedMapSize) {
    final int initialCapacity = (int) (expectedMapSize / HASHSET_DEFAULT_LOAD_FACTOR) + 1;
    return new LinkedHashSet<>(initialCapacity, HASHSET_DEFAULT_LOAD_FACTOR);
  }
}
