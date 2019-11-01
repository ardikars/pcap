/** This code is licenced under the GPL version 2. */
package pcap.common.util;

import java.util.Objects;
import pcap.common.annotation.Inclubating;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@Inclubating
public abstract class NamedMultipleObject<
        T extends MultipleObject, U extends NamedMultipleObject<T, ?>>
    implements ObjectName<T, U> {

  private final T value;
  private final String name;

  protected NamedMultipleObject(T multiKey, String name) {
    this.value = multiKey;
    this.name = name;
  }

  /**
   * Returns the number of this {@code NamedMultiKey} object.
   *
   * @return returns the number of this {@code NamedMultiKey} object.
   */
  public T value() {
    return value;
  }

  /**
   * Returns the name of this {@code NamedMultiKey} object.
   *
   * @return returns the name of this {@code NamedMultiKey} object.
   */
  @Override
  public String name() {
    return name;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (!(o instanceof NamedMultipleObject)) {
      return false;
    }
    NamedMultipleObject<?, ?> that = (NamedMultipleObject<?, ?>) o;
    return Objects.equals(value(), that.value()) && Objects.equals(name(), that.name());
  }

  @Override
  public int hashCode() {
    return Objects.hash(value(), name());
  }

  @Override
  public String toString() {
    return new StringBuilder("NamedMultiKey{")
        .append("value=")
        .append(value)
        .append(", name='")
        .append(name)
        .append('\'')
        .append('}')
        .toString();
  }
}
