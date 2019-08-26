/**
 * This code is licenced under the GPL version 2.
 */
package pcap.common.util;

/**
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 */
public interface Encoder<T, V> {

    /**
     * Encode data.
     * @param data data.
     * @param callback callback.
     */
    void encode(V data, Callback<T> callback);

}
