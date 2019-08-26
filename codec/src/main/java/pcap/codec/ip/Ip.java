/**
 * This code is licenced under the GPL version 2.
 */
package pcap.codec.ip;

import pcap.codec.AbstractPacket;

public abstract class Ip extends AbstractPacket {

	protected static abstract class AbstractPacketHeader extends Header {

		protected final byte version;

		protected AbstractPacketHeader(final byte version) {
			this.version = version;
		}

		public int getVersion() {
			return this.version & 0xf;
		}

	}

	protected static abstract class AbstractPaketBuilder extends Builder {

	}

}
