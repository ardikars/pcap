/** This code is licenced under the GPL version 2. */
package pcap.codec.ip.ip6;

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
      return FIXED_OPTIONS_LENGTH + LENGTH_UNIT * extensionLength;
    }

    @Override
    public Memory buffer() {
      if (buffer == null) {
        buffer = ALLOCATOR.allocate(length());
        buffer.writeByte(nextHeader.value());
        buffer.writeInt(extensionLength);
        if (options != null) {
          buffer.writeBytes(options);
        }
      }
      return buffer;
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
     * Extension length.
     *
     * @param extensionLength extension length.
     * @return returns {@link Builder}.
     */
    public Builder extensionLength(final int extensionLength) {
      this.extensionLength = extensionLength;
      return this;
    }

    /**
     * Options.
     *
     * @param options options.
     * @return returns this {@link Builder}.
     */
    public Builder options(final byte[] options) {
      this.options = new byte[options.length];
      System.arraycopy(options, 0, this.options, 0, this.options.length);
      return this;
    }
  }
}
