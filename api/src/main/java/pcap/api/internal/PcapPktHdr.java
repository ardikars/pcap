/**
 * This code is licenced under the GPL version 2.
 */
package pcap.api.internal;

import pcap.spi.PacketHeader;

import java.foreign.annotations.NativeGetter;
import java.foreign.annotations.NativeStruct;
import java.foreign.memory.Pointer;
import java.foreign.memory.Struct;

/**
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 */
@NativeStruct(
        value = "[${timeval}(ts)u32(caplen)u32(len)](pcap_pkthdr)",
        resolutionContext = { Timestamp.class }
)
public interface PcapPktHdr extends Struct<PcapPktHdr> {

    @NativeGetter("ts")
    Timestamp timestamp();

    @NativeGetter("caplen")
    int captureLength();

    @NativeGetter("len")
    int length();

    default String json() {
        return new StringBuilder()
                .append("{")
                .append("\"timestamp\":{")
                .append("\"second\":").append(timestamp().second()).append(",")
                .append("\"microSecond\":").append(timestamp().microSecond()).append(",")
                .append("},")
                .append("\"captureLength\":").append(captureLength()).append(",")
                .append("\"length\":").append(length())
                .append("}")
                .toString();
    }

    default PacketHeader packetHeader() {
        return new Impl(timestamp().timestamp(), captureLength(), length(), ptr());
    }

    class Impl implements PacketHeader {

        private final pcap.spi.Timestamp timestamp;
        private final int captureLangth;
        private final int length;
        private final Pointer<PcapPktHdr> ptr;

        private Impl(pcap.spi.Timestamp timestamp, int captureLangth, int length, Pointer<PcapPktHdr> ptr) {
            this.timestamp = timestamp;
            this.captureLangth = captureLangth;
            this.length = length;
            this.ptr = ptr;
        }

        @Override
        public pcap.spi.Timestamp timestamp() {
            return timestamp;
        }

        @Override
        public int captureLength() {
            return captureLangth;
        }

        @Override
        public int length() {
            return length;
        }

        public Pointer<PcapPktHdr> pointer() {
            return ptr;
        }

    }

}
