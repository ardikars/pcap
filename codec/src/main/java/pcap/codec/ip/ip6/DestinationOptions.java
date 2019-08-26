
package pcap.codec.ip.ip6;

import pcap.codec.Packet;
import pcap.codec.TransportLayer;
import pcap.common.memory.Memory;
import pcap.common.util.Validate;

public class DestinationOptions extends Options {

	private final Header header;
	private final Packet payload;

	private DestinationOptions(final Builder builder) {
		this.header = new Header(builder);
		this.payload = TransportLayer.valueOf(header.getPayloadType().getValue())
				.newInstance(builder.payloadBuffer);
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

	public static final class Header extends Options.Header {

		private final Builder builder;

		protected Header(Builder builder) {
			super(builder, builder.nextHeader);
			this.buffer = builder.buffer.slice(builder.buffer.readerIndex() - getLength(), getLength());
			this.builder = builder;
		}

		@Override
		public String toString() {
			return super.toString();
		}

		@Override
		public Builder getBuilder() {
			return builder;
		}

	}

	@Override
	public String toString() {
		return new StringBuilder("\t[ DestinationOptions Header (").append(getHeader().getLength()).append(" bytes) ]")
				.append('\n').append(header).append("\t\tpayload: ").append(payload != null ? payload.getClass().getSimpleName() : "")
				.toString();
	}

	public static final class Builder extends Options.Builder {

		public Builder() {
			super(TransportLayer.IPV6_AH);
		}

		@Override
		public DestinationOptions build() {
			return new DestinationOptions(this);
		}

		@Override
		public Packet build(final Memory buffer) {
			nextHeader = TransportLayer.valueOf(buffer.readByte());
			extensionLength = buffer.readInt();
			options = new byte[Options.Header.FIXED_OPTIONS_LENGTH
					+ Options.Header.LENGTH_UNIT * extensionLength];
			buffer.readBytes(options);
			this.buffer = buffer;
			this.payloadBuffer = buffer.slice();
			return new DestinationOptions(this);
		}

		@Override
		public void reset() {
			if (buffer != null) {
				reset(buffer.readerIndex(), Header.FIXED_OPTIONS_LENGTH);
			}
		}

		@Override
		public void reset(int offset, int length) {
			if (buffer != null) {
				Validate.notIllegalArgument(offset + length <= buffer.capacity());
				Validate.notIllegalArgument(nextHeader != null, ILLEGAL_HEADER_EXCEPTION);
				Validate.notIllegalArgument(extensionLength >= 0, ILLEGAL_HEADER_EXCEPTION);
				Validate.notIllegalArgument(options != null, ILLEGAL_HEADER_EXCEPTION);
				int index = offset;
				buffer.setByte(index, nextHeader.getValue());
				index += 1;
				buffer.setInt(index, extensionLength);
				index += 4;
				buffer.setBytes(index, options);
			}
		}

	}

}
