/** This code is licenced under the GPL version 2. */
package pcap.api.internal;

import java.foreign.NativeTypes;
import java.foreign.memory.Callback;
import java.foreign.memory.LayoutType;
import java.foreign.memory.Pointer;
import java.util.concurrent.TimeoutException;
import pcap.api.internal.foreign.callback.windows_callback;
import pcap.api.internal.foreign.mapping.PcapMapping;
import pcap.api.internal.foreign.mapping.WindowsPcapMapping;
import pcap.api.internal.foreign.pcap_header;
import pcap.api.internal.foreign.struct.windows_structs;
import pcap.common.annotation.Inclubating;
import pcap.spi.PacketBuffer;
import pcap.spi.PacketHandler;
import pcap.spi.PacketHeader;
import pcap.spi.exception.ErrorException;
import pcap.spi.exception.error.BreakException;

/**
 * Windows {@code Pcap} handle.
 *
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 */
@Inclubating
public class WindowsPcap extends Pcap implements pcap.spi.Pcap.WinPcap {

  private Callback<windows_callback.pcap_handler> oneshotCallback;

  public WindowsPcap(Pointer<pcap_header.pcap> pcap) {
    super(pcap);
  }

  public WindowsPcap(Pointer<pcap_header.pcap> pcap, int netmask) {
    super(pcap, netmask);
  }

  @Override
  public Handle event() {
    return new HandleImpl(WindowsPcapMapping.MAPPING.pcap_getevent(pcap));
  }

  @Override
  public <T> void loop(int count, PacketHandler<T> handler, T args)
      throws BreakException, ErrorException {
    synchronized (PcapMapping.LOCK) {
      if (LOGGER.isDebugEnabled()) {
        LOGGER.debug("Looping {} packets.", count == -1 ? "infinite" : count);
        LOGGER.debug("Packets processed with {}.", handler.getClass().getName());
      }
      Callback<windows_callback.pcap_handler> callback =
          scope.allocateCallback(
              windows_callback.pcap_handler.class,
              (user, header, packets) -> {
                windows_structs.pcap_pkthdr pcap_pkthdr = header.get();
                windows_structs.timeval ts = pcap_pkthdr.timestamp();
                PacketHeader packetHeader =
                    new WindowsPacketHeader(
                        null,
                        header,
                        new DefaultTimestamp(ts.second(), ts.microSecond()),
                        pcap_pkthdr.captureLength(),
                        pcap_pkthdr.length());
                handler.gotPacket(
                    args,
                    packetHeader,
                    PcapPacketBuffer.fromReference(packets, packetHeader.captureLength()));
              });

      int result = WindowsPcapMapping.MAPPING.pcap_loop(pcap, count, callback, Pointer.ofNull());
      if (result == 0) {
        return;
      } else if (result == -2) {
        throw new BreakException("");
      } else {
        throw new ErrorException(Pointer.toString(PcapMapping.MAPPING.pcap_geterr(pcap)));
      }
    }
  }

  @Override
  public void nextEx(PacketBuffer packetBuffer, PacketHeader packetHeader)
      throws BreakException, TimeoutException, ErrorException {
    synchronized (PcapMapping.LOCK) {
      PcapPacketBuffer pcap_packet_buffer = (PcapPacketBuffer) packetBuffer;
      WindowsPacketHeader pcap_packet_header = (WindowsPacketHeader) packetHeader;

      if (pcap_packet_buffer.ptr == null) {
        return;
      }

      int result =
          WindowsPcapMapping.MAPPING.pcap_next_ex(
              pcap, pcap_packet_header.ptr, pcap_packet_buffer.ptr);

      if (result == 0) {
        throw new TimeoutException("");
      } else if (result == 1) {
        windows_structs.pcap_pkthdr pcapPacketHeader = pcap_packet_header.ptr.get().get();
        windows_structs.timeval ts = pcapPacketHeader.timestamp();

        pcap_packet_header.timestamp.second = ts.second();
        pcap_packet_header.timestamp.microSecond = ts.microSecond();
        pcap_packet_header.captureLength = pcapPacketHeader.captureLength();
        pcap_packet_header.length = pcapPacketHeader.length();
      } else {
        if (result == -2) {
          throw new BreakException("");
        } else {
          throw new ErrorException(Pointer.toString(PcapMapping.MAPPING.pcap_geterr(pcap)));
        }
      }
    }
  }

  @Override
  public <T> void dispatch(int count, PacketHandler<T> handler, T args)
      throws BreakException, ErrorException {
    synchronized (PcapMapping.LOCK) {
      if (LOGGER.isDebugEnabled()) {
        LOGGER.debug("Dispatcing {} packets", count);
      }
      if (oneshotCallback == null) {
        oneshotCallback =
            scope.allocateCallback(
                windows_callback.pcap_handler.class,
                (user, header, packets) -> {
                  windows_structs.pcap_pkthdr pcap_pkthdr = header.get();
                  windows_structs.timeval ts = pcap_pkthdr.timestamp();
                  DefaultTimestamp timestamp = new DefaultTimestamp(ts.second(), ts.microSecond());
                  PacketHeader packetHeader =
                      new WindowsPacketHeader(
                          null,
                          header,
                          timestamp,
                          pcap_pkthdr.captureLength(),
                          pcap_pkthdr.length());
                  handler.gotPacket(
                      args,
                      packetHeader,
                      PcapPacketBuffer.fromReference(packets, packetHeader.captureLength()));
                });
      }
      if (oneshotCallback != null) {
        int result =
            WindowsPcapMapping.MAPPING.pcap_dispatch(
                pcap, count, oneshotCallback, Pointer.ofNull());
        if (result < 0) {
          if (result == -1) {
            throw new ErrorException(Pointer.toString(PcapMapping.MAPPING.pcap_geterr(pcap)));
          } else if (result == -2) {
            throw new BreakException("");
          } else {
            throw new ErrorException("Generic error.");
          }
        } else if (result == 0) {
          LOGGER.debug("No packets were read from a capture.");
        }
      }
    }
  }

  @Override
  public <T> T allocate(Class<T> cls) throws IllegalArgumentException {
    synchronized (PcapMapping.LOCK) {
      if (cls.isAssignableFrom(PacketBuffer.class)) {
        final Pointer<Pointer<Byte>> pcap_ptr_to_buffer =
            scope.allocate(NativeTypes.UINT8.pointer());
        return (T) PcapPacketBuffer.fromPointer(pcap_ptr_to_buffer, 0);
      } else if (cls.isAssignableFrom(PacketHeader.class)) {
        final Pointer<Pointer<windows_structs.pcap_pkthdr>> pcap_ptr_to_packet_header =
            scope.allocate(LayoutType.ofStruct(windows_structs.pcap_pkthdr.class).pointer());
        return (T)
            new WindowsPacketHeader(
                pcap_ptr_to_packet_header,
                pcap_ptr_to_packet_header.get(),
                new DefaultTimestamp(0, 0),
                0,
                0);
      }
      throw new IllegalArgumentException(
          "A class (" + cls + ") doesn't supported for this operation.");
    }
  }

  public static class HandleImpl implements Handle {

    public final Pointer<Void> ptr;

    private HandleImpl(Pointer<Void> ptr) {
      this.ptr = ptr;
    }

    @Override
    public long address() {
      return ptr.addr();
    }
  }
}
