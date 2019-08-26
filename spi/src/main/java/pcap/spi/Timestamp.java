/**
 * This code is licenced under the GPL version 2.
 */
package pcap.spi;

/**
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 */
public interface Timestamp {

    long second();

    int microSecond();

    enum Precision {
        MICRO(0), NANO(1);

        private final int value;

        Precision(int value) {
            this.value = value;
        }

        public int value() {
            return value;
        }

    }

    enum Type {

        HOST(0), HOST_LOWPREC(1), HOST_HIPREC(2), ADAPTER(3), ADAPTER_UNSYNCED(4);

        private final int value;

        Type(int value) {
            this.value = value;
        }

        public int value() {
            return value;
        }

    }

}
