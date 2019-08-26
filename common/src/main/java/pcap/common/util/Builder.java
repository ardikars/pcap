/**
 * This code is licenced under the GPL version 2.
 */
package pcap.common.util;

/**
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 */
public interface Builder<T, V> {

    /**
     * Build object.
     * @return object.
     */
    T build();

    /**
     * Build object with given argument.
     * @param value value.
     * @return object.
     */
    T build(V value);

}
