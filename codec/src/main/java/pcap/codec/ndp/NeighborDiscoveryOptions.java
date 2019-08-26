package pcap.codec.ndp;

import pcap.codec.AbstractPacket;
import pcap.codec.Packet;
import pcap.codec.UnknownPacket;
import pcap.common.memory.Memory;
import pcap.common.util.NamedNumber;
import pcap.common.util.Strings;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 */
public class NeighborDiscoveryOptions extends AbstractPacket {

    private final Header header;
    private final Packet payload;

    /**
     * Builde Neighbor Discovery Options packet.
     * @param builder builder.
     */
    public NeighborDiscoveryOptions(Builder builder) {
        this.header = new Header(builder);
        this.payload = null;
        payloadBuffer = builder.payloadBuffer;
    }

    @Override
    public Header getHeader() {
        return header;
    }

    @Override
    public Packet getPayload() {
        return payload;
    }

    public static class Header extends AbstractPacket.Header {

        private final List<Option> options;
        private int length;

        private final Builder builder;

        private Header(Builder builder) {
            this.options = builder.options;
            this.buffer = builder.buffer.slice(builder.buffer.readerIndex() - getLength(), getLength());
            this.builder = builder;
        }

        public List<Option> getOptions() {
            return options;
        }

        @Override
        public <T extends NamedNumber> T getPayloadType() {
            return (T) UnknownPacket.UNKNOWN_PAYLOAD_TYPE;
        }

        @Override
        public int getLength() {
            if (length == 0) {
                for (Option option : this.options) {
                    length += option.getLength() << 3;
                }
            }
            return length;
        }

        @Override
        public Memory getBuffer() {
            if (buffer == null) {
                buffer = ALLOCATOR.allocate(getLength());
                for (Option option : options) {
                    buffer.writeByte(option.getType().getValue());
                    buffer.writeByte(option.getLength());
                    buffer.writeBytes(option.getData());
                    int paddingLength = (option.getLength() << 3) - (option.getData().length + 2);
                    for (int i = 0; i < paddingLength; i++) {
                        buffer.writeByte(0);
                    }
                }
            }
            return buffer;
        }

        @Override
        public Builder getBuilder() {
            return builder;
        }

        @Override
        public String toString() {
            return new StringBuilder()
                    .append("\toptions: ").append(options).append('\n')
                    .toString();
        }

    }

    @Override
    public String toString() {
        return new StringBuilder("[ NeighborDiscoveryOptions Header (").append(getHeader().getLength()).append(" bytes) ]")
                .append('\n').append(header).append("\tpayload: ").append(payload != null ? payload.getClass().getSimpleName() : "")
                .toString();
    }

    public static class OptionType extends NamedNumber<Byte, OptionType> {

        public static final OptionType SOURCE_LINK_LAYER_ADDRESS =
                new OptionType((byte) 1, "Source link layer addresss");

        public static final OptionType TARGET_LINK_LAYER_ADDRESS =
                new OptionType((byte) 2, "Target link layer addresss");

        public static final OptionType PREFIX_INFORMATION =
                new OptionType((byte) 3, "Prefix information");

        public static final OptionType REDIRECT_HEADER =
                new OptionType((byte) 4, "Redirect header");

        public static final OptionType MTU =
                new OptionType((byte) 5, "MTU");

        private static Map<Byte, OptionType> registry =
                new HashMap<Byte, OptionType>();

        protected OptionType(Byte value, String name) {
            super(value, name);
        }

        static {
            registry.put(SOURCE_LINK_LAYER_ADDRESS.getValue(), SOURCE_LINK_LAYER_ADDRESS);
            registry.put(TARGET_LINK_LAYER_ADDRESS.getValue(), TARGET_LINK_LAYER_ADDRESS);
            registry.put(PREFIX_INFORMATION.getValue(), PREFIX_INFORMATION);
            registry.put(REDIRECT_HEADER.getValue(), REDIRECT_HEADER);
            registry.put(MTU.getValue(), MTU);
        }

    }

    public static final class Option implements Serializable  {

        private static final long serialVersionUID = -7839083814311096470L;

        private OptionType type;
        private byte length;
        private byte[] data;

        private Option() {

        }

        /**
         * Create new instance on {@link Option} class.
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

        public OptionType getType() {
            return type;
        }

        public byte getLength() {
            return length;
        }

        /**
         * Get option.
         * @return returns option.
         */
        public byte[] getData() {
            byte[] data = new byte[this.data.length];
            System.arraycopy(this.data, 0, data, 0, data.length);
            return data;
        }

        @Override
        public String toString() {
            return new StringBuilder("[")
                    .append("Type: ")
                    .append(this.getType())
                    .append(", Data: ")
                    .append(Strings.toHexString(this.getData()))
                    .append("]").toString();
        }

    }

    public static class Builder extends AbstractPacket.Builder {

        private List<Option> options = new ArrayList<Option>();

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
            while (buffer.isReadable(2)) {
                final OptionType type = OptionType.registry.get(buffer.readByte());
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
