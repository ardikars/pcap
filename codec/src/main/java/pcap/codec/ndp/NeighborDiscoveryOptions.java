/** This code is licenced under the GPL version 2. */
package pcap.codec.ndp;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import pcap.codec.AbstractPacket;
import pcap.codec.Packet;
import pcap.codec.UnknownPacket;
import pcap.common.annotation.Inclubating;
import pcap.common.memory.Memory;
import pcap.common.util.NamedNumber;
import pcap.common.util.Strings;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@Inclubating
public class NeighborDiscoveryOptions extends AbstractPacket {

  private final Header header;
  private final Packet payload;
  private final Builder builder;

  /**
   * Builde Neighbor Discovery Options packet.
   *
   * @param builder builder.
   */
  public NeighborDiscoveryOptions(Builder builder) {
    this.header = new Header(builder);
    this.payload = null;
    payloadBuffer = builder.payloadBuffer;
    this.builder = builder;
  }

  @Override
  public Header header() {
    return header;
  }

  @Override
  public Packet payload() {
    return payload;
  }

  @Override
  public Builder builder() {
    return builder;
  }

  @Override
  public Memory buffer() {
    return header().buffer();
  }

  @Override
  public String toString() {
    return Strings.toStringBuilder(this)
        .add("header", header)
        .add("payload", payload != null ? payload.getClass().getSimpleName() : "(None)")
        .toString();
  }

  public static class Header extends AbstractPacket.Header {

    private final List<Option> options;
    private final Builder builder;
    private int length;

    private Header(Builder builder) {
      this.options = builder.options;
      this.buffer = slice(builder.buffer, length());
      this.builder = builder;
    }

    public List<Option> options() {
      return options;
    }

    @SuppressWarnings("TypeParameterUnusedInFormals")
    @Override
    public <T extends NamedNumber> T payloadType() {
      return (T) UnknownPacket.UNKNOWN_PAYLOAD_TYPE;
    }

    @Override
    public int length() {
      if (length == 0) {
        for (Option option : this.options) {
          length += option.length() << 3;
        }
      }
      return length;
    }

    @Override
    public Memory buffer() {
      if (buffer == null) {
        buffer = ALLOCATOR.allocate(length());
        for (Option option : options) {
          buffer.writeByte(option.type().value());
          buffer.writeByte(option.length());
          buffer.writeBytes(option.data());
          int paddingLength = (option.length() << 3) - (option.data().length + 2);
          for (int i = 0; i < paddingLength; i++) {
            buffer.writeByte(0);
          }
        }
      }
      return buffer;
    }

    @Override
    public Builder builder() {
      return builder;
    }

    @Override
    public String toString() {
      return new StringBuilder().append("\toptions: ").append(options).append('\n').toString();
    }
  }

  public static class OptionType extends NamedNumber<Byte, OptionType> {

    public static final OptionType SOURCE_LINK_LAYER_ADDRESS =
        new OptionType((byte) 1, "Source link layer addresss");

    public static final OptionType TARGET_LINK_LAYER_ADDRESS =
        new OptionType((byte) 2, "Target link layer addresss");

    public static final OptionType PREFIX_INFORMATION =
        new OptionType((byte) 3, "Prefix information");

    public static final OptionType REDIRECT_HEADER = new OptionType((byte) 4, "Redirect header");

    public static final OptionType MTU = new OptionType((byte) 5, "MTU");

    private static Map<Byte, OptionType> REGISTRY = new HashMap<>();

    static {
      REGISTRY.put(SOURCE_LINK_LAYER_ADDRESS.value(), SOURCE_LINK_LAYER_ADDRESS);
      REGISTRY.put(TARGET_LINK_LAYER_ADDRESS.value(), TARGET_LINK_LAYER_ADDRESS);
      REGISTRY.put(PREFIX_INFORMATION.value(), PREFIX_INFORMATION);
      REGISTRY.put(REDIRECT_HEADER.value(), REDIRECT_HEADER);
      REGISTRY.put(MTU.value(), MTU);
    }

    protected OptionType(Byte value, String name) {
      super(value, name);
    }
  }

  public static final class Option implements Serializable {

    private static final long serialVersionUID = -7839083814311096470L;

    private OptionType type;
    private byte length;
    private byte[] data;

    private Option() {}

    /**
     * Create new instance on {@link Option} class.
     *
     * @param type type.
     * @param data data.
     * @return returns {@link Option} object.
     */
    public static Option newInstance(OptionType type, byte[] data) {
      byte[] newData = new byte[data.length];
      System.arraycopy(data, 0, newData, 0, newData.length);
      Option option = new Option();
      option.type = type;
      option.data = newData;
      option.length = (byte) ((option.data.length + 2 + 7) >> 3);
      return option;
    }

    public OptionType type() {
      return type;
    }

    public byte length() {
      return length;
    }

    /**
     * Get option.
     *
     * @return returns option.
     */
    public byte[] data() {
      byte[] data = new byte[this.data.length];
      System.arraycopy(this.data, 0, data, 0, data.length);
      return data;
    }

    @Override
    public String toString() {
      return Strings.toStringBuilder(this)
          .add("type", type())
          .add("data", Strings.hex(data()))
          .toString();
    }
  }

  public static class Builder extends AbstractPacket.Builder {

    private List<Option> options = new ArrayList<>();

    private Memory buffer;
    private Memory payloadBuffer;

    public Builder options(List<Option> options) {
      this.options = options;
      return this;
    }

    @Override
    public Packet build() {
      return new NeighborDiscoveryOptions(this);
    }

    @Override
    public Packet build(Memory buffer) {
      resetIndex(buffer);
      while (buffer.isReadable(2)) {
        final OptionType type = OptionType.REGISTRY.get(buffer.readByte());
        byte lengthField = buffer.readByte();
        int dataLength = lengthField * 8;
        if (dataLength < 2) {
          break;
        }
        dataLength -= 2;
        if (!buffer.isReadable(dataLength)) {
          break;
        }
        byte[] data = new byte[dataLength];
        buffer.readBytes(data, 0, dataLength);
        options.add(Option.newInstance(type, data));
      }
      this.buffer = buffer;
      this.payloadBuffer = buffer.slice();
      return new NeighborDiscoveryOptions(this);
    }
  }
}
