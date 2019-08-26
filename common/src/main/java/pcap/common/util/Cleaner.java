/**
 * This code is licenced under the GPL version 2.
 */
package pcap.common.util;

/**
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 */
public interface Cleaner<T> {

    /**
     * Cleaner.
     * @param buffer buffer.
     */
    void clean(T buffer);

    /**
     * Cleaner
     * @param buffer buffer.
     * @param callback callback.
     */
    void clean(T buffer, Callback<Void> callback);

}
