/** This code is licenced under the GPL version 2. */
package pcap.common.util;

import java.io.Serializable;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
public class MultipleObject<K> implements Serializable {

  private static final long serialVersionUID = -7486266343955776290L;

  private final transient Set<K> keys;

  protected MultipleObject(Set<K> keys) {
    this.keys = keys;
  }

  /**
   * Create {@code MultiKey} object.
   *
   * @param keys keys.
   * @param <K> key type.
   * @return returns {@code MultiKey} object.
   */
  @SuppressWarnings("unchecked")
  public static <K> MultipleObject<K> of(K... keys) {
    return new MultipleObject<>(new HashSet<>(Arrays.asList(keys)));
  }

  @Override
  public boolean equals(Object o) {
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    if (this == o) {
      return true;
    }
    MultipleObject<?> that = (MultipleObject<?>) o;
    return keys.equals(that.keys);
  }

  @Override
  public int hashCode() {
    return Objects.hash(keys);
  }

  @Override
  public String toString() {
    return String.valueOf(keys);
  }
}
