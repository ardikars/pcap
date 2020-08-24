/** This code is licenced under the GPL version 2. */
package pcap.codec.ip.ip6;

import java.util.Arrays;
import java.util.Objects;
import pcap.codec.AbstractPacket;
import pcap.codec.TransportLayer;
import pcap.codec.ip.Ip6;
import pcap.common.annotation.Inclubating;
import pcap.common.memory.Memory;
import pcap.common.util.Strings;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@Inclubating
public abstract class Options extends AbstractPacket {

  protected abstract static class Header extends Ip6.ExtensionHeader {

    public static final int FIXED_OPTIONS_LENGTH = 6;
    public static final int LENGTH_UNIT = 8;

    protected final TransportLayer nextHeader;
    protected final int extensionLength;
    protected final byte[] options;

    protected Header(final Builder builder, TransportLayer nextHeader) {
      this.nextHeader = nextHeader;
      this.extensionLength = builder.extensionLength;
      this.options = builder.options;
    }

    /**
     * Next protocol type.
     *
     * @return returns {@link TransportLayer}.
     */
    public TransportLayer nextHeader() {
      return nextHeader;
    }

    /**
     * Extension length.
     *
     * @return returns extension length.
     */
    public int extensionLength() {
      return extensionLength;
    }

    /**
     * Options.
     *
     * @return returns options.
     */
    public byte[] options() {
      if (options != null) {
        byte[] data = new byte[options.length];
        System.arraycopy(options, 0, data, 0, data.length);
        return data;
      }
      return new byte[0];
    }

    @Override
    public TransportLayer payloadType() {
      return nextHeader;
    }

    @Override
    public int length() {
      return options == null ? 2 : options.length + 2;
    }

    @Override
    public Memory buffer() {
      if (buffer == null) {
        buffer = ALLOCATOR.allocate(length());
        buffer.writeByte(nextHeader.value());
        buffer.writeByte(extensionLength);
        if (options != null) {
          buffer.writeBytes(options);
        }
      }
      return buffer;
    }

    @Override
    public boolean equals(Object o) {
      if (this == o) return true;
      if (o == null || getClass() != o.getClass()) return false;
      Header header = (Header) o;
      return extensionLength == header.extensionLength
          && nextHeader.equals(header.nextHeader)
          && Arrays.equals(options, header.options);
    }

    @Override
    public int hashCode() {
      int result = Objects.hash(nextHeader, extensionLength);
      result = 31 * result + Arrays.hashCode(options);
      return result;
    }

    @Override
    public String toString() {
      return Strings.toStringBuilder(this)
          .add("nextHeader", nextHeader)
          .add("extensionLength", extensionLength)
          .add("options", Strings.hex(options))
          .toString();
    }
  }

  protected abstract static class Builder extends AbstractPacket.Builder {

    protected TransportLayer nextHeader;
    protected int extensionLength;
    protected byte[] options;

    protected Memory buffer;
    protected Memory payloadBuffer;

    public Builder(final TransportLayer nextHeader) {
      this.nextHeader = nextHeader;
    }

    /**
     * Next header.
     *
     * @param nextHeader next header.
     * @return returns {@link Builder}.
     */
    public abstract Builder nextHeader(TransportLayer nextHeader);

    /**
     * Extension length.
     *
     * @param extensionLength extension length.
     * @return returns {@link Builder}.
     */
    public abstract Builder extensionLength(final int extensionLength);

    /**
     * Options.
     *
     * @param options options.
     * @return returns this {@link Builder}.
     */
    public abstract Builder options(final byte[] options);
  }
}
