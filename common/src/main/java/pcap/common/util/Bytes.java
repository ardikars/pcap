/**
 * This code is licenced under the GPL version 2.
 */
package pcap.common.util;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 */
public final class Bytes {

    public Bytes() { }

    /**
     * Byte to byte array.
     * @param value value.
     * @return byte array.
     * @since 1.0.0
     */
    public static byte[] toByteArray(final byte value) {
        return new byte[] { value };
    }

    /**
     * Short to byte array.
     * @param value value.
     * @return byte array.
     * @since 1.0.0
     */
    public static byte[] toByteArray(final short value) {
        return toByteArray(value, ByteOrder.BIG_ENDIAN);
    }

    /**
     * Short to byte array.
     * @param value value.
     * @param bo byte order.
     * @return byte array.
     * @since 1.0.0
     */
    public static byte[] toByteArray(final short value, final ByteOrder bo) {
        if (bo.equals(ByteOrder.BIG_ENDIAN)) {
            return new byte[] { (byte) ((value >> 0) & 0xff), (byte) ((value >> 8) & 0xff) };
        } else {
            return new byte[] { (byte) ((value >> 8) & 0xff), (byte) ((value >> 0) & 0xff) };
        }
    }

    /**
     * Short array to byte array.
     * @param value value.
     * @return byte array.
     * @since 1.0.0
     */
    public static byte[] toByteArray(final short[] value) {
        return toByteArray(value, ByteOrder.BIG_ENDIAN);
    }

    /**
     * Short array to byte array.
     * @param value value.
     * @param bo byte order.
     * @return byte array.
     * @since 1.0.0
     */
    public static byte[] toByteArray(final short[] value, final ByteOrder bo) {
        return toByteArray(value, 0, value.length, bo);
    }

    /**
     * Short array to byte array.
     * @param value value.
     * @param offset offset.
     * @param length length.
     * @param bo byte order.
     * @return byte array.
     * @since 1.0.0
     */
    public static byte[] toByteArray(final short[] value, final int offset, final int length, final ByteOrder bo) {
        Validate.notInBounds(value, offset, length);
        byte[] array = new byte[length << 1];
        if (bo.equals(ByteOrder.BIG_ENDIAN)) {
            for (int i = offset; i < length; i++) {
                short x = value[i];
                int j = i << 1;
                array[j++] = (byte) ((x >> 0) & 0xff);
                array[j++] = (byte) ((x >> 8) & 0xff);
            }
            return array;
        } else {
            for (int i = offset; i < length; i++) {
                short x = value[i];
                int j = i << 1;
                array[j++] = (byte) ((x >> 8) & 0xff);
                array[j++] = (byte) ((x >> 0) & 0xff);
            }
            return array;
        }
    }

    /**
     * Int to byte array.
     * @param value value.
     * @return byte array.
     * @since 1.0.0
     */
    public static byte[] toByteArray(final int value) {
        return toByteArray(value, ByteOrder.BIG_ENDIAN);
    }

    /**
     * Int to byte array.
     * @param value value.
     * @param bo byte order.
     * @return byte array.
     * @since 1.0.0
     */
    public static byte[] toByteArray(final int value, final ByteOrder bo) {
        if (bo.equals(ByteOrder.BIG_ENDIAN)) {
            return new byte[] {
                    (byte) ((value >> 0) & 0xff),
                    (byte) ((value >> 8) & 0xff),
                    (byte) ((value >> 16 & 0xff)),
                    (byte) ((value >> 24 & 0xff))
            };
        } else {
            return new byte[] {
                    (byte) ((value >> 24) & 0xff),
                    (byte) ((value >> 16) & 0xff),
                    (byte) ((value >> 8) & 0xff),
                    (byte) ((value >> 0) & 0xff)
            };
        }
    }

    /**
     * Int array to byte array.
     * @param value value.
     * @return byte array.
     * @since 1.0.0
     */
    public static byte[] toByteArray(final int[] value) {
        return toByteArray(value, ByteOrder.BIG_ENDIAN);
    }

    /**
     * Int array to byte array.
     * @param value value.
     * @param bo byte order.
     * @return byte array.
     * @since 1.0.0
     */
    public static byte[] toByteArray(final int[] value, final ByteOrder bo) {
        return toByteArray(value, 0, value.length, bo);
    }

    /**
     * Int array to byte array.
     * @param value value.
     * @param offset offset.
     * @param length length.
     * @param bo byte order.
     * @return byte array.
     * @since 1.0.0
     */
    public static byte[] toByteArray(final int[] value, final int offset, final int length, final ByteOrder bo) {
        Validate.notInBounds(value, offset, length);
        byte[] array = new byte[length << 2];
        if (bo.equals(ByteOrder.BIG_ENDIAN)) {
            for (int i = offset; i < length; i++) {
                int x = value[i];
                int j = i << 2;
                array[j++] = (byte) ((x >> 0) & 0xff);
                array[j++] = (byte) ((x >> 8) & 0xff);
                array[j++] = (byte) ((x >> 16) & 0xff);
                array[j++] = (byte) ((x >> 24) & 0xff);
            }
            return array;
        } else {
            for (int i = offset; i < length; i++) {
                int x = value[i];
                int j = i << 2;
                array[j++] = (byte) ((x >> 24) & 0xff);
                array[j++] = (byte) ((x >> 16) & 0xff);
                array[j++] = (byte) ((x >> 8) & 0xff);
                array[j++] = (byte) ((x >> 0) & 0xff);
            }
            return array;
        }
    }

    /**
     * Long to byte array.
     * @param value value.
     * @return byte array.
     * @since 1.0.0
     */
    public static byte[] toByteArray(final long value) {
        return toByteArray(value, ByteOrder.BIG_ENDIAN);
    }

    /**
     * Long to byte array.
     * @param value value.
     * @param bo byte order.
     * @return byte array.
     * @since 1.0.0
     */
    public static byte[] toByteArray(final long value, final ByteOrder bo) {
        if (bo.equals(ByteOrder.BIG_ENDIAN)) {
            return new byte[] {
                    (byte) ((value >> 0) & 0xff),
                    (byte) ((value >> 8) & 0xff),
                    (byte) ((value >> 16) & 0xff),
                    (byte) ((value >> 24) & 0xff),
                    (byte) ((value >> 32) & 0xff),
                    (byte) ((value >> 40) & 0xff),
                    (byte) ((value >> 48) & 0xff),
                    (byte) ((value >> 56) & 0xff)
            };
        } else {
            return new byte[] {
                    (byte) ((value >> 56) & 0xff),
                    (byte) ((value >> 48) & 0xff),
                    (byte) ((value >> 40) & 0xff),
                    (byte) ((value >> 32) & 0xff),
                    (byte) ((value >> 24) & 0xff),
                    (byte) ((value >> 16) & 0xff),
                    (byte) ((value >> 8) & 0xff),
                    (byte) ((value >> 0) & 0xff)
            };
        }
    }

    /**
     * Long array to byte array.
     * @param value value.
     * @return byte array.
     * @since 1.0.0
     */
    public static byte[] toByteArray(final long[] value) {
        return toByteArray(value, ByteOrder.BIG_ENDIAN);
    }

    /**
     * Long array to byte array.
     * @param value value.
     * @param bo byte order.
     * @return byte array.
     */
    public static byte[] toByteArray(final long[] value, final ByteOrder bo) {
        return toByteArray(value, 0, value.length, bo);
    }

    /**
     * Long array to byte array.
     * @param value value.
     * @param offset offset.
     * @param length length.
     * @param bo byte order.
     * @return byte array.
     * @since 1.0.0
     */
    public static byte[] toByteArray(final long[] value, final int offset, final int length, final ByteOrder bo) {
        Validate.notInBounds(value, offset, length);
        byte[] array = new byte[length << 3];
        if (bo.equals(ByteOrder.BIG_ENDIAN)) {
            for (int i = offset; i < length; i++) {
                long x = value[i];
                int j = i << 3;
                array[j++] = (byte) ((x >> 0) & 0xff);
                array[j++] = (byte) ((x >> 8) & 0xff);
                array[j++] = (byte) ((x >> 16) & 0xff);
                array[j++] = (byte) ((x >> 24) & 0xff);
                array[j++] = (byte) ((x >> 32) & 0xff);
                array[j++] = (byte) ((x >> 40) & 0xff);
                array[j++] = (byte) ((x >> 48) & 0xff);
                array[j++] = (byte) ((x >> 56) & 0xff);
            }
            return array;
        } else {
            for (int i = offset; i < length; i++) {
                long x = value[i];
                int j = i << 3;
                array[j++] = (byte) ((x >> 56) & 0xff);
                array[j++] = (byte) ((x >> 48) & 0xff);
                array[j++] = (byte) ((x >> 40) & 0xff);
                array[j++] = (byte) ((x >> 32) & 0xff);
                array[j++] = (byte) ((x >> 24) & 0xff);
                array[j++] = (byte) ((x >> 16) & 0xff);
                array[j++] = (byte) ((x >> 8) & 0xff);
                array[j++] = (byte) ((x >> 0) & 0xff);
            }
            return array;
        }
    }

    /**
     * ByteBuffer to byte array.
     * @param byteBuffer ByteBuffer.
     * @return byte array.
     * @since 1.0.0
     */
    public static byte[] toByteArray(final ByteBuffer byteBuffer) {
        Validate.nullPointer(byteBuffer);
        if (!byteBuffer.hasRemaining()) {
            byteBuffer.flip();
        }
        byte[] buffer = new byte[byteBuffer.remaining()];
        byteBuffer.get(buffer);
        return buffer;
    }

}
