
package pcap.codec.ip;

import pcap.codec.AbstractPacket;
import pcap.codec.Packet;
import pcap.codec.TransportLayer;
import pcap.common.memory.Memory;
import pcap.common.net.Inet6Address;
import pcap.common.util.Validate;

public class Ip6 extends Ip {

	private final Header header;
	private final Packet payload;

	private Ip6(final Builder builder) {
		this.header = new Header(builder);
		this.payload = TransportLayer.valueOf(this.header.getPayloadType().getValue())
				.newInstance(builder.payloadBuffer);
	}

	@Override
	public Header getHeader() {
		return header;
	}

	@Override
	public Packet getPayload() {
		return payload;
	}
	public static final class Header extends AbstractPacketHeader {

		public static final int IPV6_HEADER_LENGTH = 40;

		private final byte trafficClass;
		private final int flowLabel;
		private final short payloadLength;
		private final TransportLayer nextHeader;
		private final byte hopLimit;
		private final Inet6Address sourceAddress;
		private final Inet6Address destinationAddress;

		private final Builder builder;

		protected Header(final Builder builder) {
			super((byte) 0x06);
			this.trafficClass = builder.trafficClass;
			this.flowLabel = builder.flowLabel;
			this.payloadLength = builder.payloadLength;
			this.nextHeader = builder.nextHeader;
			this.hopLimit = builder.hopLimit;
			this.sourceAddress = builder.sourceAddress;
			this.destinationAddress = builder.destinationAddress;
			this.buffer = builder.buffer.slice(builder.buffer.readerIndex() - getLength(), getLength());
			this.builder = builder;
		}

		public int getTrafficClass() {
			return trafficClass & 0xff;
		}

		public int getFlowLabel() {
			return flowLabel & 0xfffff;
		}

		public int getPayloadLength() {
			return payloadLength & 0xffff;
		}

		public TransportLayer getNextHeader() {
			return nextHeader;
		}

		public int getHopLimit() {
			return hopLimit & 0xff;
		}

		public Inet6Address getSourceAddress() {
			return sourceAddress;
		}

		public Inet6Address getDestinationAddress() {
			return destinationAddress;
		}

		@Override
		public TransportLayer getPayloadType() {
			return nextHeader;
		}

		@Override
		public int getLength() {
			return IPV6_HEADER_LENGTH;
		}

		@Override
		public Memory getBuffer() {
			if (buffer == null) {
				buffer = ALLOCATOR.allocate(getLength());
				buffer.writeInt((super.version & 0xf) << 28 | (trafficClass & 0xff) << 20 | flowLabel & 0xfffff);
				buffer.writeShort(payloadLength);
				buffer.writeByte(nextHeader.getValue());
				buffer.writeByte(hopLimit);
				buffer.writeBytes(sourceAddress.toBytes());
				buffer.writeBytes(destinationAddress.toBytes());
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
					.append("\tversion: ").append(version).append('\n')
					.append("\ttrafficClass: ").append(trafficClass).append('\n')
					.append("\tflowLabel: ").append(flowLabel).append('\n')
					.append("\tpayloadLength: ").append(payloadLength).append('\n')
					.append("\tnextHeader: ").append(nextHeader).append('\n')
					.append("\thopLimit: ").append(hopLimit).append('\n')
					.append("\tsourceAddress: ").append(sourceAddress).append('\n')
					.append("\tdestinationAddress: ").append(destinationAddress).append('\n')
					.toString();
		}

	}

	@Override
	public String toString() {
		return new StringBuilder("[ Ip6 Header (").append(getHeader().getLength()).append(" bytes) ]")
				.append('\n').append(header).append("\tpayload: ").append(payload != null ? payload.getClass().getSimpleName() : "")
				.toString();
	}

	public static final class Builder extends AbstractPaketBuilder {

		private byte trafficClass;
		private int flowLabel;
		private short payloadLength;
		private TransportLayer nextHeader;
		private byte hopLimit;
		private Inet6Address sourceAddress;
		private Inet6Address destinationAddress;

		private Memory buffer;
		private Memory payloadBuffer;

		public Builder trafficClass(final int trafficClass) {
			this.trafficClass = (byte) (trafficClass & 0xff);
			return this;
		}

		public Builder flowLabel(final int flowLabel) {
			this.flowLabel = flowLabel & 0xfffff;
			return this;
		}

		public Builder payloadLength(final int payloadLength) {
			this.payloadLength = (short) (payloadLength & 0xffff);
			return this;
		}

		public Builder nextHeader(final TransportLayer nextHeader) {
			this.nextHeader = nextHeader;
			return this;
		}

		public Builder hopLimit(final int hopLimit) {
			this.hopLimit = (byte) (hopLimit & 0xff);
			return this;
		}

		public Builder sourceAddress(final Inet6Address sourceAddress) {
			this.sourceAddress = sourceAddress;
			return this;
		}

		public Builder destinationAddress(final Inet6Address destinationAddress) {
			this.destinationAddress = destinationAddress;
			return this;
		}

		public Builder payloadBuffer(final Memory buffer) {
			this.payloadBuffer = buffer;
			return this;
		}

		@Override
		public Packet build() {
			return new Ip6(this);
		}

		@Override
		public Packet build(final Memory buffer) {
			int iscratch = buffer.readInt();
			this.trafficClass = (byte) (iscratch >> 20 & 0xff);
			this.flowLabel = iscratch & 0xfffff;
			this.payloadLength = buffer.readShort();
			this.nextHeader = TransportLayer.valueOf(buffer.readByte());
			this.hopLimit = buffer.readByte();
			byte[] addrBuf = new byte[Inet6Address.IPV6_ADDRESS_LENGTH];
			buffer.readBytes(addrBuf);
			this.sourceAddress = Inet6Address.valueOf(addrBuf);
			addrBuf = new byte[Inet6Address.IPV6_ADDRESS_LENGTH];
			buffer.readBytes(addrBuf);
			this.destinationAddress = Inet6Address.valueOf(addrBuf);
			this.buffer = buffer;
			this.payloadBuffer = buffer.slice();
			return new Ip6(this);
		}

		@Override
		public void reset() {
			if (buffer != null) {
				reset(buffer.readerIndex(), Header.IPV6_HEADER_LENGTH);
			}
		}

		@Override
		public void reset(int offset, int length) {
			if (buffer != null) {
                Validate.notIllegalArgument(offset + length <= buffer.capacity());
                Validate.notIllegalArgument(trafficClass >= 0, ILLEGAL_HEADER_EXCEPTION);
                Validate.notIllegalArgument(flowLabel >= 0, ILLEGAL_HEADER_EXCEPTION);
                Validate.notIllegalArgument(payloadLength >= 0, ILLEGAL_HEADER_EXCEPTION);
                Validate.notIllegalArgument(nextHeader != null, ILLEGAL_HEADER_EXCEPTION);
                Validate.notIllegalArgument(hopLimit >= 0, ILLEGAL_HEADER_EXCEPTION);
                Validate.notIllegalArgument(sourceAddress != null, ILLEGAL_HEADER_EXCEPTION);
                Validate.notIllegalArgument(destinationAddress != null, ILLEGAL_HEADER_EXCEPTION);
                int index = offset;
                int scratch = ((trafficClass << 20) & 0xff) | (flowLabel & 0xfffff);
			    buffer.setInt(offset, scratch);
			    index += 4;
			    buffer.setShort(offset, payloadLength);
			    index += 2;
			    buffer.setByte(index, nextHeader.getValue());
			    index += 1;
			    buffer.setByte(index, hopLimit);
			    index += 1;
			    buffer.setBytes(index, sourceAddress.toBytes());
			    index += Inet6Address.IPV6_ADDRESS_LENGTH;
			    buffer.setBytes(index, destinationAddress.toBytes());
			}
		}

	}

	public abstract static class ExtensionHeader extends AbstractPacket.Header {

	}

}
