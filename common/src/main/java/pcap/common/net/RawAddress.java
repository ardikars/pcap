/**
 * This code is licenced under the GPL version 2.
 */
package pcap.common.net;

/**
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 */
public class RawAddress implements Address {

    private final byte[] address;

    private RawAddress(byte[] address) {
        this.address = address;
    }

    /**
     * Create instance of {@link RawAddress}.
     * @param bytes byte array.
     * @return returns {@link RawAddress}/
     */
    public static RawAddress valueOf(byte[] bytes) {
        return new RawAddress(bytes);
    }

    @Override
    public byte[] getAddress() {
        byte[] data = new byte[address.length];
        System.arraycopy(address, 0, data, 0, data.length);
        return data;
    }

}
