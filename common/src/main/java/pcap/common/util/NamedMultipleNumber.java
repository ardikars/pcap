/**
 * This code is licenced under the GPL version 2.
 */
package pcap.common.util;

import java.util.Objects;

/**
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 */
public abstract class NamedMultipleNumber<T extends MultipleNumber, U extends NamedMultipleNumber<T, ?>> implements ObjectName<T, U> {

    private final T value;
    private final String name;

    protected NamedMultipleNumber(T multiKey, String name) {
        this.value = multiKey;
        this.name = name;
    }

    /**
     * Returns the number of this {@code NamedMultiKeyNumber} object.
     * @return returns the multi key number of this {@code NamedMultiKeyNumber} object.
     */
    @Override
    public T getValue() {
        return value;
    }

    /**
     * Returns the name of this {@code NamedMultiKeyNumber} object.
     * @return returns the name of this {@code NamedMultiKeyNumber} object.
     */
    @Override
    public String getName() {
        return name;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof NamedMultipleNumber)) {
            return false;
        }
        NamedMultipleNumber<?, ?> that = (NamedMultipleNumber<?, ?>) o;
        return Objects.equals(getValue(), that.getValue())
                && Objects.equals(getName(), that.getName());
    }

    @Override
    public int hashCode() {
        return Objects.hash(getValue(), getName());
    }

}
