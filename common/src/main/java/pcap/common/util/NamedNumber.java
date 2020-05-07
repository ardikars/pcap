/** This code is licenced under the GPL version 2. */
package pcap.common.util;

import pcap.common.annotation.Inclubating;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@Inclubating
public abstract class NamedNumber<T extends Number, U extends NamedNumber<T, ?>>
    implements ObjectName<T, U> {

  private static final long serialVersionUID = -7754849362562086047L;

  private final T value;
  private final String name;

  protected NamedNumber(T value, String name) {
    this.value = value;
    this.name = name;
  }

  /**
   * Returns the number of this {@code NamedNumber} object.
   *
   * @return returns the number of this {@code NamedNumber} object.
   */
  public T value() {
    return this.value;
  }

  /**
   * Returns the name of this {@code NamedNumber} object.
   *
   * @return returns the name of this {@code NamedNumber} object.
   */
  @Override
  public String name() {
    return this.name;
  }

  @Override
  public boolean equals(Object obj) {
    if (obj == null) {
      return false;
    }
    if (obj == this) {
      return true;
    }
    if (!(obj instanceof NamedNumber)) {
      return false;
    }
    return this.value.equals(this.getClass().cast(obj).value());
  }

  @Override
  public int hashCode() {
    return value.hashCode();
  }

  @Override
  public String toString() {
    return Strings.toStringBuilder(this).add("name", name).add("value", value).toString();
  }
}
