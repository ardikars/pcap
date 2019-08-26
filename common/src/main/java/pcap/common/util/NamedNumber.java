/**
 * This code is licenced under the GPL version 2.
 */
package pcap.common.util;

/**
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 */
public abstract class NamedNumber<T extends Number, U extends NamedNumber<T, ?>> implements ObjectName<T, U> {

    private static final long serialVersionUID = -7754849362562086047L;

    private final T value;
    private final String name;

    protected NamedNumber(T value, String name) {
        this.value = value;
        this.name = name;
    }

    /**
     * Returns the number of this {@code NamedNumber} object.
     * @return returns the number of this {@code NamedNumber} object.
     */
    @Override
    public T getValue() {
        return this.value;
    }

    /**
     * Returns the name of this {@code NamedNumber} object.
     * @return returns the name of this {@code NamedNumber} object.
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
        if (!(obj instanceof NamedNumber)) {
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
                .append("]").toString();
    }

}
