/** This code is licenced under the GPL version 2. */
package pcap.common.util;

import pcap.common.annotation.Inclubating;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@Inclubating
public abstract class NamedObject<T, U extends NamedObject<T, ?>> implements ObjectName<T, U> {

  private static final long serialVersionUID = -2413391980553692553L;

  private final T value;
  private final String name;

  protected NamedObject(T value, String name) {
    this.value = value;
    this.name = name;
  }

  /**
   * Returns the value of this {@code NamedObject} object.
   *
   * @return returns the value of this {@code NamedObject} object.
   */
  public T getValue() {
    return this.value;
  }

  /**
   * Returns the name of this {@code NamedObject} object.
   *
   * @return returns the name of this {@code NamedObject} object.
   */
  @Override
  public String getName() {
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
    if (obj.getClass() != this.getClass()) {
      return false;
    }
    if (!(obj instanceof NamedObject)) {
      return false;
    }
    return this.value.equals(this.getClass().cast(obj).getValue());
  }

  @Override
  public int hashCode() {
    return value.hashCode();
  }

  @Override
  public String toString() {
    return new StringBuilder("[Value: ")
        .append(this.value)
        .append(", Name: ")
        .append(this.name)
        .append("]")
        .toString();
  }
}
