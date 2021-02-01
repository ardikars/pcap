package pcap.codec.ip.extension.ip6;

import pcap.codec.AbstractPacket;
import pcap.common.util.Strings;
import pcap.common.util.Validate;
import pcap.spi.PacketBuffer;
import pcap.spi.annotation.Incubating;

import java.util.ArrayList;
import java.util.List;

/**
 * Options:
 *
 * <p>1. Option Type 8-bit identifier of the type of option.
 *
 * <p>2. Opt Data Len 8-bit unsigned integer. Length of the Option Data field of this option, in
 * octets.
 *
 * <p>3.Option Data Variable-length field. Option-Type-specific data.
 *
 * <p>The sequence of options within a header must be processed strictly in the order they appear in
 * the header; a receiver must not, for example, scan through the header looking for a particular
 * kind of option and process that option prior to processing all preceding ones.
 *
 * <p>The Option Type identifiers are internally encoded such that their highest-order 2 bits
 * specify the action that must be taken if the processing IPv6 node does not recognize the Option
 * Type:
 *
 * <p>00 - skip over this option and continue processing the header.
 *
 * <p>01 - discard the packet.
 *
 * <p>10 - discard the packet and, regardless of whether or not the packet's Destination Address was
 * a multicast address, send an ICMP Parameter Problem, Code 2, message to the packet's Source
 * Address, pointing to the unrecognized Option Type.
 *
 * <p>11 - discard the packet and, only if the packet's Destination Address was not a multicast
 * address, send an ICMP Parameter Problem, Code 2, message to the packet's Source Address, pointing
 * to the unrecognized Option Type.
 */
@Incubating
public final class Option {

  private final int type;
  private final int length;
  private final byte[] data;

  private Option(int type, int length, byte[] data) {
    this.type = type;
    this.length = length;
    this.data = data;
  }

  public int type() {
    return type;
  }

  public int length() {
    return length;
  }

  public byte[] data() {
    return data;
  }

  @Override
  public String toString() {
    return Strings.toStringBuilder(this)
        .add("type", type())
        .add("length", length())
        .add("data", Strings.hex(data()))
        .toString();
  }

  static class Header extends AbstractPacket {

    private static final int FIXED_OPTIONS_LENGTH = 6;
    private static final int LENGTH_UNIT = 8;

    private final long nextHeader;
    private final long headerExtensionLength;
    private final long options;

    private final int maxOptionLength;

    protected Header(PacketBuffer buffer) {
      super(buffer);
      this.nextHeader = offset;
      this.headerExtensionLength = nextHeader + 1;
      this.options = headerExtensionLength + 1;
      this.maxOptionLength =
          FIXED_OPTIONS_LENGTH + LENGTH_UNIT * buffer.getByte(headerExtensionLength);
    }

    @Incubating
    public int nextHeader() {
      return buffer.getByte(nextHeader) & 0xFF;
    }

    @Incubating
    public Header nextHeader(int value) {
      buffer.setByte(nextHeader, value);
      return this;
    }

    @Incubating
    public int headerExtensionLength() {
      return buffer.getByte(headerExtensionLength) & 0xFF;
    }

    @Incubating
    public Header headerExtensionLength(int value) {
      buffer.setByte(headerExtensionLength, value);
      return this;
    }

    @Incubating
    public List<Option> options() {
      byte[] bytes = new byte[FIXED_OPTIONS_LENGTH + LENGTH_UNIT * headerExtensionLength()];
      buffer.getBytes(options, bytes);
      List<Option> options = new ArrayList<>();
      int optLenIdx = 1;
      while (optLenIdx < bytes.length) {
        byte[] data = new byte[bytes[optLenIdx] & 0xFF];
        System.arraycopy(bytes, optLenIdx + 1, data, 0, data.length);
        options.add(new Option(bytes[optLenIdx - 1], optLenIdx, data));
        optLenIdx = optLenIdx + data.length + 1;
      }
      return options;
    }

    @Incubating
    public Header options(List<Option> opts) {
      int size = 0;
      for (int i = 0; i < opts.size(); i++) {
        size = size + (opts.get(i).length + 2);
      }
      int optTypeIdx = 0;
      byte[] bytes = new byte[size];
      for (int i = 0; i < opts.size(); i++) {
        bytes[optTypeIdx] = (byte) opts.get(i).type;
        bytes[optTypeIdx + 1] = (byte) opts.get(i).length;
        System.arraycopy(opts.get(i).data, 0, bytes, bytes[optTypeIdx + 2], bytes[optTypeIdx + 1]);
        optTypeIdx = optTypeIdx + bytes[optTypeIdx + 1] + 2;
      }
      buffer.setBytes(options, bytes, 0, Math.min(bytes.length, maxOptionLength));
      return this;
    }

    @Override
    public int size() {
      if (maxOptionLength == 0L) {
        Validate.notIllegalState(buffer.readableBytes() >= 8, "buffer size is not sufficient.");
      }
      return 2 + FIXED_OPTIONS_LENGTH + LENGTH_UNIT * buffer.getByte(headerExtensionLength);
    }

    @Override
    public String toString() {
      return Strings.toStringBuilder(this)
          .add("nextHeader", nextHeader())
          .add("headerExtensionLength", headerExtensionLength())
          .add("options", options())
          .toString();
    }
  }
}
