/**
 * This code is licenced under the GPL version 2.
 */
package pcap.codec.ip.ip6;

import pcap.codec.AbstractPacket;
import pcap.codec.Packet;
import pcap.codec.TransportLayer;
import pcap.common.memory.Memory;
import pcap.common.util.NamedNumber;
import pcap.common.util.Validate;

import java.util.HashMap;
import java.util.Map;

/**
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 */
public class Fragment extends AbstractPacket {

	private final Header header;
	private final Packet payload;

	private Fragment(final Builder builder) {
		this.header = new Header(builder);
		this.payload = TransportLayer.valueOf(header.getPayloadType().getValue())
				.newInstance(builder.payloadBuffer);
		payloadBuffer = builder.payloadBuffer;
	}

	@Override
	public Packet.Header getHeader() {
		return header;
	}

	@Override
	public Packet getPayload() {
		return payload;
	}

	public static final class Header extends AbstractPacket.Header {

		public static final int FIXED_FRAGMENT_HEADER_LENGTH = 8;

		private final TransportLayer nextHeader;
		private final short fragmentOffset;
		private final FlagType flagType;
		private final int identification;

		private final Builder builder;

		private Header(final Builder builder) {
			this.nextHeader = builder.nextHeader;
			this.fragmentOffset = builder.fragmentOffset;
			this.flagType = builder.flagType;
			this.identification = builder.identification;
			this.buffer = builder.buffer.slice(builder.buffer.readerIndex() - getLength(), getLength());
			this.builder = builder;
		}

		public TransportLayer getNextHeader() {
			return nextHeader;
		}

		public int getFragmentOffset() {
			return fragmentOffset & 0x1fff;
		}

		public FlagType getFlagType() {
			return flagType;
		}

		public int getIdentification() {
			return identification;
		}

		@Override
		public TransportLayer getPayloadType() {
			return nextHeader;
		}

		@Override
		public int getLength() {
			return FIXED_FRAGMENT_HEADER_LENGTH;
		}

		@Override
		public Memory getBuffer() {
			if (buffer == null) {
				buffer = ALLOCATOR.allocate(getLength());
				buffer.writeByte(nextHeader.getValue());
				buffer.writeByte(0); // reserved
				buffer.writeShort((fragmentOffset & 0x1fff) << 3
						| flagType.getValue() & 0x1);
				buffer.writeInt(identification);
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
					.append("\t\tnextHeader: ").append(nextHeader).append('\n')
					.append("\t\tfragmentOffset: ").append(fragmentOffset).append('\n')
					.append("\t\tflagType: ").append(flagType).append('\n')
					.append("\t\tidentification: ").append(identification).append('\n')
					.toString();
		}

	}

	@Override
	public String toString() {
		return new StringBuilder("\t[ Fragment Header (").append(getHeader().getLength()).append(" bytes) ]")
				.append('\n').append(header).append("\t\tpayload: ").append(payload != null ? payload.getClass().getSimpleName() : "")
				.toString();
	}

	public static final class Builder extends AbstractPacket.Builder {

		private TransportLayer nextHeader;
		private short fragmentOffset;
		private FlagType flagType;
		private int identification;

		private Memory buffer;
		private Memory payloadBuffer;

		public Builder nextHeader(TransportLayer nextHeader) {
			this.nextHeader = nextHeader;
			return this;
		}

		public Builder fragmentOffset(int fragmentOffset) {
			this.fragmentOffset = (short) (fragmentOffset & 0x1fff);
			return this;
		}

		public Builder flagType(FlagType flagType) {
			this.flagType = flagType;
			return this;
		}

		public Builder identification(int identification) {
			this.identification = identification;
			return this;
		}

		@Override
		public Fragment build() {
			return new Fragment(this);
		}

		@Override
		public Fragment build(final Memory buffer) {
			this.nextHeader = TransportLayer.valueOf(buffer.readByte());
			buffer.readByte(); // reserved
			short sscratch = buffer.readShort();
			this.fragmentOffset = (short) (sscratch >> 3 & 0x1fff);
			this.flagType = FlagType.valueOf((byte) (sscratch & 0x1));
			this.identification = buffer.readInt();
			this.buffer = buffer;
			this.payloadBuffer = buffer.slice();
			return new Fragment(this);
		}

		@Override
		public void reset() {
			if (buffer != null) {
				reset(buffer.readerIndex(), Header.FIXED_FRAGMENT_HEADER_LENGTH);
			}
		}

		@Override
		public void reset(int offset, int length) {
			if (buffer != null) {
				Validate.notIllegalArgument(offset + length <= buffer.capacity());
				Validate.notIllegalArgument(nextHeader != null, ILLEGAL_HEADER_EXCEPTION);
				Validate.notIllegalArgument(fragmentOffset >= 0, ILLEGAL_HEADER_EXCEPTION);
				Validate.notIllegalArgument(flagType != null, ILLEGAL_HEADER_EXCEPTION);
				Validate.notIllegalArgument(identification >= 0, ILLEGAL_HEADER_EXCEPTION);
				int index = offset;
				buffer.setByte(index, nextHeader.getValue());
				index += 1;
				buffer.setByte(index, 0); // reserved
				index += 1;
				int sscratch = (fragmentOffset & 0x1fff) << 3 | flagType.getValue() & 0x1;
				buffer.setShort(index, sscratch);
				index += 2;
				buffer.setIndex(index, identification);
			}
		}

	}

	public static final class FlagType extends NamedNumber<Byte, FlagType> {

		public static final FlagType LAST_FRAGMENT = new FlagType((byte) 0, "Last fragment.");

		public static final FlagType MORE_FRAGMENT = new FlagType((byte) 1, "More fragment.");

		public static final FlagType UNKNOWN = new FlagType((byte) -1, "UNKNOWN.");

		private static final Map<Byte, FlagType> REGISTRY
				= new HashMap<Byte, FlagType>();

		protected FlagType(Byte value, String name) {
			super(value, name);
		}
		public static FlagType register(final FlagType flagType) {
			REGISTRY.put(flagType.getValue(), flagType);
			return flagType;
		}

		/**
		 * Get flag type from value.
		 * @param flag value.
		 * @return returns {@link FlagType}.
		 */
		public static FlagType valueOf(final byte flag) {
			FlagType flagType = REGISTRY.get(flag);
			if (flagType == null) {
				return UNKNOWN;
			}
			return flagType;
		}

	}


}
