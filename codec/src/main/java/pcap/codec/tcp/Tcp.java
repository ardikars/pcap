/**
 * This code is licenced under the GPL version 2.
 */
package pcap.codec.tcp;

import pcap.codec.AbstractPacket;
import pcap.codec.Packet;
import pcap.codec.ApplicationLayer;
import pcap.common.memory.Memory;
import pcap.common.util.Strings;
import pcap.common.util.Validate;

/**
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 */
public class Tcp extends AbstractPacket {

    private final Header header;
    private final Packet payload;

    private Tcp(final Builder builder) {
        this.header = new Header(builder);
        this.payload = ApplicationLayer.valueOf(this.header.getPayloadType().getValue())
                .newInstance(builder.payloadBuffer);
        this.payloadBuffer = builder.payloadBuffer;
    }

    @Override
    public Header getHeader() {
        return header;
    }

    @Override
    public Packet getPayload() {
        return payload;
    }
    public static final class Header extends AbstractPacket.Header {

        public static final int TCP_HEADER_LENGTH = 20;

        private final short sourcePort;
        private final short destinationPort;
        private final int sequence;
        private final int acknowledge;
        private final byte dataOffset;
        private final TcpFlags flags;
        private final short windowSize;
        private final short checksum;
        private final short urgentPointer;
        private final byte[] options;

        private final Builder builder;

        private Header(final Builder builder) {
            this.sourcePort = builder.sourcePort;
            this.destinationPort = builder.destinationPort;
            this.sequence = builder.sequence;
            this.acknowledge = builder.acknowledge;
            this.dataOffset = builder.dataOffset;
            this.flags = builder.flags;
            this.windowSize = builder.windowSize;
            this.checksum = builder.checksum;
            this.urgentPointer = builder.urgentPointer;
            this.options = builder.options;
            this.buffer = builder.buffer.slice(builder.buffer.readerIndex() - getLength(), getLength());
            this.builder = builder;
        }

        public int getSourcePort() {
            return sourcePort & 0xffff;
        }

        public int getDestinationPort() {
            return destinationPort & 0xffff;
        }

        public int getSequence() {
            return sequence;
        }

        public int getAcknowledge() {
            return acknowledge;
        }

        public int getDataOffset() {
            return dataOffset & 0xf;
        }

        public TcpFlags getFlags() {
            return flags;
        }

        public int getWindowSize() {
            return windowSize & 0xffff;
        }

        public int getChecksum() {
            return checksum & 0xffff;
        }

        public int getUrgentPointer() {
            return urgentPointer & 0xffff;
        }

        /**
         * Get options.
         * @return returns options.
         */
        public byte[] getOptions() {
            if (options == null) {
                return new byte[0];
            }
            byte[] buffer = new byte[this.options.length];
            System.arraycopy(options, 0, buffer, 0, buffer.length);
            return buffer;
        }

        @Override
        public ApplicationLayer getPayloadType() {
            return ApplicationLayer.valueOf(destinationPort);
        }

        @Override
        public int getLength() {
            int length = TCP_HEADER_LENGTH;
            if (this.options != null) {
                length += this.options.length;
            }
            return length;
        }

        @Override
        public Memory getBuffer() {
            if (buffer == null) {
                buffer = ALLOCATOR.allocate(getLength());
                buffer.writeShort(this.sourcePort);
                buffer.writeShort(this.destinationPort);
                buffer.writeInt(this.sequence);
                buffer.writeInt(this.acknowledge);
                buffer.writeShort((this.flags.getShortValue() & 0x1ff) | (this.dataOffset & 0xf) << 12);
                buffer.writeShort(this.windowSize);
                buffer.writeShort(this.checksum);
                buffer.writeShort(this.urgentPointer);
                if (this.options != null) {
                    buffer.writeBytes(this.options);
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
                    .append("\tsourcePort: ").append(sourcePort).append('\n')
                    .append("\tdestinationPort: ").append(destinationPort).append('\n')
                    .append("\tsequence: ").append(sequence).append('\n')
                    .append("\tacknowledge: ").append(acknowledge).append('\n')
                    .append("\tdataOffset: ").append(dataOffset).append('\n')
                    .append("\tflags: ").append(flags).append('\n')
                    .append("\twindowSize: ").append(windowSize).append('\n')
                    .append("\tchecksum: ").append(checksum).append('\n')
                    .append("\turgentPointer: ").append(urgentPointer).append('\n')
                    .append("\toptions: ").append(Strings.toHexString(options)).append('\n')
                    .toString();
        }

    }

    @Override
    public String toString() {
        return new StringBuilder("[ Tcp Header (").append(getHeader().getLength()).append(" bytes) ]")
                .append('\n').append(header).append("\tpayload: ").append(payload != null ? payload.getClass().getSimpleName() : "")
                .toString();
    }

    public static class Builder extends AbstractPacket.Builder {

        private short sourcePort;
        private short destinationPort;
        private int sequence;
        private int acknowledge;
        private byte dataOffset;
        private TcpFlags flags;
        private short windowSize;
        private short checksum;
        private short urgentPointer;
        private byte[] options;

        private Memory buffer;
        private Memory payloadBuffer;

        public Builder sourcePort(int sourcePort) {
            this.sourcePort = (short) (sourcePort & 0xffff);
            return this;
        }

        public Builder destinationPort(int destinationPort) {
            this.destinationPort = (short) (destinationPort & 0xffff);
            return this;
        }

        public Builder sequence(int sequence) {
            this.sequence = sequence;
            return this;
        }

        public Builder acknowledge(int acknowledge) {
            this.acknowledge = acknowledge;
            return this;
        }

        public Builder dataOffset(int dataOffset) {
            this.dataOffset = (byte) (dataOffset & 0xf);
            return this;
        }

        public Builder flags(TcpFlags flags) {
            this.flags = flags;
            return this;
        }

        public Builder windowsSize(int windowSize) {
            this.windowSize = (short) (windowSize & 0xffff);
            return this;
        }

        public Builder checksum(int checksum) {
            this.checksum = (short) (checksum & 0xffff);
            return this;
        }

        public Builder urgentPointer(int urgentPointer) {
            this.urgentPointer = (short) (urgentPointer & 0xffff);
            return this;
        }

        public Builder options(byte[] options) {
            this.options = Validate.nullPointer(options, new byte[0]);
            return this;
        }

        public Builder payloadBuffer(Memory buffer) {
            this.payloadBuffer = buffer;
            return this;
        }

        @Override
        public Packet build() {
            return new Tcp(this);
        }

        @Override
        public Packet build(Memory buffer) {
            this.sourcePort = buffer.readShort();
            this.destinationPort = buffer.readShort();
            this.sequence = buffer.readInt();
            this.acknowledge = buffer.readInt();
            short flags = buffer.readShort();
            this.dataOffset = (byte) (flags >> 12 & 0xf);
            this.flags = new TcpFlags.Builder().build((short) (flags & 0x1ff));
            this.windowSize = buffer.readShort();
            this.checksum = buffer.readShort();
            this.urgentPointer = buffer.readShort();
            if (this.dataOffset > 5) {
                int optionLength = (this.dataOffset << 2) - Header.TCP_HEADER_LENGTH;
                if (buffer.capacity() < Header.TCP_HEADER_LENGTH + optionLength) {
                    optionLength = buffer.capacity() - Header.TCP_HEADER_LENGTH;
                }
                this.options = new byte[optionLength];
                buffer.readBytes(options);
                int length = 20 + optionLength;
                this.payloadBuffer = buffer.copy(length, buffer.capacity() - length);
            }
            this.buffer = buffer;
            this.payloadBuffer = buffer.slice();
            return new Tcp(this);
        }

        @Override
        public void reset() {
            if (buffer != null) {
                reset(buffer.readerIndex(), Header.TCP_HEADER_LENGTH);
            }
        }

        @Override
        public void reset(int offset, int length) {
            if (buffer != null) {
                Validate.notIllegalArgument(offset + length <= buffer.capacity());
                Validate.notIllegalArgument(sourcePort >= 0, ILLEGAL_HEADER_EXCEPTION);
                Validate.notIllegalArgument(destinationPort >= 0, ILLEGAL_HEADER_EXCEPTION);
                Validate.notIllegalArgument(sequence >= 0, ILLEGAL_HEADER_EXCEPTION);
                Validate.notIllegalArgument(acknowledge >= 0, ILLEGAL_HEADER_EXCEPTION);
                Validate.notIllegalArgument(flags != null, ILLEGAL_HEADER_EXCEPTION);
                Validate.notIllegalArgument(windowSize >= 0, ILLEGAL_HEADER_EXCEPTION);
                Validate.notIllegalArgument(checksum >= 0, ILLEGAL_HEADER_EXCEPTION);
                Validate.notIllegalArgument(urgentPointer >= 0, ILLEGAL_HEADER_EXCEPTION);
                Validate.notIllegalArgument(dataOffset >= 0, ILLEGAL_HEADER_EXCEPTION);
                Validate.notIllegalArgument(options != null, ILLEGAL_HEADER_EXCEPTION);
                int index = offset;
                buffer.setShort(index, sourcePort);
                index += 2;
                buffer.setShort(index, destinationPort);
                index += 2;
                buffer.setInt(index, sequence);
                index += 4;
                buffer.setInt(index, acknowledge);
                index += 4;
                int tmp = ((dataOffset << 12) & 0xf) | (flags.getShortValue() & 0x1ff);
                buffer.setShort(index, tmp);
                index += 2;
                buffer.setShort(index, windowSize);
                index += 2;
                buffer.setShort(index, checksum);
                index += 2;
                buffer.setShort(index, urgentPointer);
                index += 2;
                if (dataOffset > 5 && options != null) {
                    buffer.setBytes(index, options);
                }
            }
        }

    }

}
