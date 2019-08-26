/**
 * This code is licenced under the GPL version 2.
 */
package pcap.common.util;

import java.nio.ByteBuffer;
import java.util.regex.Pattern;

/**
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 */
public final class Hexs {

    private static final Pattern NO_SEPARATOR_HEX_STRING_PATTERN
            = Pattern.compile("\\A([0-9a-fA-F][0-9a-fA-F])+\\z");

    private static final String HEXDUMP_PRETTY_HEADER = ""
            + "         +-------------------------------------------------+\n"
            + "         |  0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f |\n"
            + "+--------+-------------------------------------------------+--------+\n";

    private static final String HEXDUMP_PRETTY_FOOTER = ""
            + "+--------+---------------------------------"
            + "----------------+--------+";

    private static final char[] HEXDUMP_TABLE;


    /**
     * {@link ByteBuffer} to hex string.
     * @param buffer buffer.
     * @return returns hex string.
     */
    public static String toHexString(final ByteBuffer buffer) {
        return toHexString(buffer, 0, buffer.capacity());
    }

    /**
     * {@link ByteBuffer} to hex string.
     * @param buffer buffer.
     * @param offset offset.
     * @param length length.
     * @return returns hex string.
     */
    public static String toHexString(final ByteBuffer buffer, final int offset, final int length) {
        if (length == 0) {
            return "";
        }
        int endIndex = offset + length;
        char[] buf = new char[length << 1];

        int srcIdx = offset;
        int dstIdx = 0;
        for (; srcIdx < endIndex; srcIdx++, dstIdx += 2) {
            System.arraycopy(
                    HEXDUMP_TABLE, (buffer.get(srcIdx) & 0xFF) << 1,
                    buf, dstIdx, 2);
        }
        return new String(buf);
    }

    /**
     * {@link ByteBuffer} to hex string.
     * @param buffer buffer.
     * @return returns hex string.
     */
    public static String toHexString(final byte[] buffer) {
        return toHexString(buffer, 0, buffer.length);
    }

    /**
     * {@link ByteBuffer} to hex string.
     * @param buffer buffer.
     * @param offset offset.
     * @param length length.
     * @return returns hex string.
     */
    public static String toHexString(final byte[] buffer, final int offset, final int length) {
        if (length == 0) {
            return "";
        }
        int endIndex = offset + length;
        char[] buf = new char[length << 1];

        int srcIdx = offset;
        int dstIdx = 0;
        for (; srcIdx < endIndex; srcIdx++, dstIdx += 2) {
            System.arraycopy(
                    HEXDUMP_TABLE, (buffer[srcIdx] & 0xFF) << 1,
                    buf, dstIdx, 2);
        }
        return new String(buf);
    }

    /**
     * Byte array to hex dump format.
     * @param data byte array.
     * @return hex dump format.
     * @since 1.0.0
     */
    public static String toPrettyHexDump(final byte[] data) {
        return toPrettyHexDump(data, 0, data.length);
    }

    /**
     * Byte array to hex dump format.
     * @param data byte array.
     * @param offset offset.
     * @param length length.
     * @return hex dump format.
     * @since 1.0.0
     */
    public static String toPrettyHexDump(final byte[] data, final int offset, final int length) {
        Validate.notInBounds(data, offset, length);
        StringBuilder result = new StringBuilder();
        StringBuilder builder = new StringBuilder();
        int pos = offset;
        int max = length;
        int lineNumber = 0;
        builder.append(HEXDUMP_PRETTY_HEADER);
        while (pos < max) {
            builder.append(String.format("%08d", lineNumber++) + " | ");
            int lineMax = Math.min(max - pos, 16);
            for (int i = 0; i < lineMax; i++) {
                int index = (data[pos + i] & 0xFF) << 1;
                builder.append(new String(new char[] {HEXDUMP_TABLE[index], HEXDUMP_TABLE[++index]}));
                builder.append(" ");
            }
            while (builder.length() < 48) {
                builder.append(" ");
            }
            builder.append("| ");
            for (int i = 0; i < lineMax; i++) {
                char c = (char) data[pos + i];
                if (c < 32 || c > 127) {
                    c = '.';
                }
                builder.append(c);
            }
            builder.append("\n");
            result.append(builder);
            builder.setLength(0);
            pos += 16;
        }
        result.append(HEXDUMP_PRETTY_FOOTER);
        return result.toString();
    }

    /**
     * Byte buffer to hex dump format.
     * @param buffer byte buffer.
     * @param offset offset.
     * @param length length.
     * @return hex dump format.
     * @since 1.1.0
     */
    public static String toPrettyHexDump(ByteBuffer buffer, int offset, int length) {
        Validate.notInBounds(buffer.capacity(), offset, length);
        StringBuilder result = new StringBuilder();
        StringBuilder builder = new StringBuilder();
        int pos = offset;
        int max = length;
        int lineNumber = 0;
        builder.append(HEXDUMP_PRETTY_HEADER);
        while (pos < max) {
            builder.append(String.format("%08d", lineNumber++) + " | ");
            int lineMax = Math.min(max - pos, 16);
            for (int i = 0; i < lineMax; i++) {
                int index = (buffer.get(pos + i) & 0xFF) << 1;
                builder.append(new String(new char[] {HEXDUMP_TABLE[index], HEXDUMP_TABLE[++index]}));
                builder.append(" ");
            }
            while (builder.length() < 48) {
                builder.append(" ");
            }
            builder.append("| ");
            for (int i = 0; i < lineMax; i++) {
                char c = buffer.getChar(pos + i);
                if (c < 32 || c > 127) {
                    c = '.';
                }
                builder.append(c);
            }
            builder.append("\n");
            result.append(builder);
            builder.setLength(0);
            pos += 16;
        }
        result.append(HEXDUMP_PRETTY_FOOTER);
        return result.toString();
    }

    /**
     * Hex stream to byte array.
     * @param hexStream hex stream.
     * @return byte array.
     * @since 1.0.0
     */
    public static byte[] parseHex(String hexStream) {
        Validate.nullPointer(hexStream);
        if (hexStream.startsWith("0x")) {
            hexStream = hexStream.substring(2);
        }
        hexStream = hexStream.replaceAll("\\s+", "").trim();
        if (!NO_SEPARATOR_HEX_STRING_PATTERN.matcher(hexStream).matches()) {
            throw new IllegalArgumentException();
        }
        int len = hexStream.length();
        byte[] data = new byte[len >> 1];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hexStream.charAt(i), 16) << 4)
                    + Character.digit(hexStream.charAt(i + 1), 16));
        }
        return data;
    }

    static {
        HEXDUMP_TABLE = new char[256 * 4];
        final char[] digits = "0123456789abcdef".toCharArray();
        for (int i = 0; i < 256; i++) {
            HEXDUMP_TABLE[ i << 1     ] = digits[i >>> 4 & 0x0F];
            HEXDUMP_TABLE[(i << 1) + 1] = digits[i       & 0x0F];
        }
    }

}
