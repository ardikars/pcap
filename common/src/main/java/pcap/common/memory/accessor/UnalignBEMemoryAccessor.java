/**
 * This code is licenced under the GPL version 2.
 */
package pcap.common.memory.accessor;

/**
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 */
class UnalignBEMemoryAccessor extends AbstractMemoryAcessor {

    @Override
    public short getShort(long addr) {
        return UNSAFE.getShort(addr);
    }

    @Override
    public short getShortLE(long addr) {
        return Short.reverseBytes(UNSAFE.getShort(addr));
    }

    @Override
    public int getInt(long addr) {
        return UNSAFE.getInt(addr);
    }

    @Override
    public int getIntLE(long addr) {
        return Integer.reverseBytes(UNSAFE.getInt(addr));
    }

    @Override
    public long getLong(long addr) {
        return UNSAFE.getLong(addr);
    }

    @Override
    public long getLongLE(long addr) {
        return Long.reverseBytes(UNSAFE.getLong(addr));
    }

    @Override
    public void setShort(long addr, int val) {
        UNSAFE.putShort(addr, (short) val);
    }

    @Override
    public void setShortLE(long addr, int val) {
        UNSAFE.putShort(addr, Short.reverseBytes((short) val));
    }

    @Override
    public void setInt(long addr, int val) {
        UNSAFE.putInt(addr, val);
    }

    @Override
    public void setIntLE(long addr, int val) {
        UNSAFE.putInt(addr, Integer.reverseBytes(val));
    }

    @Override
    public void setLong(long addr, long val) {
        UNSAFE.putLong(addr, val);
    }

    @Override
    public void setLongLE(long addr, long val) {
        UNSAFE.putLong(addr, Long.reverseBytes(val));
    }

}
