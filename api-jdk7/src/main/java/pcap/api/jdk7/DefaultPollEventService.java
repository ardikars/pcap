package pcap.api.jdk7;

import com.sun.jna.Native;
import com.sun.jna.NativeLibrary;
import com.sun.jna.Platform;
import com.sun.jna.Pointer;
import pcap.api.Event;
import pcap.api.EventService;
import pcap.spi.Pcap;

class DefaultPollEventService implements EventService {

  private static final boolean REGISTERED;
  private static final int EINTR = 4;

  private static final short POLLIN = 0x1;
  private static final int FD_OFFSET = 0;
  private static final int EVENTS_OFFSET = FD_OFFSET + 4;
  private static final int REVENTS_OFFSET = EVENTS_OFFSET + 2;

  static {
    if (!Platform.isWindows()) {
      com.sun.jna.Native.register(
          DefaultPollEventService.class, NativeLibrary.getInstance(Platform.C_LIBRARY_NAME));
      REGISTERED = true;
    } else {
      REGISTERED = false;
    }
  }

  DefaultPcap pcap;
  Pointer pfds;

  public DefaultPollEventService() {
    this.pcap = null;
    this.pfds = null;
  }

  @Override
  public EventService open(Pcap pcap) {
    if (REGISTERED) {
      DefaultPcap defaultPcap = (DefaultPcap) pcap;
      Pointer pfds = new Pointer(Native.malloc(8));
      pfds.setInt(
          FD_OFFSET,
          NativeMappings.PlatformDependent.INSTANCE.pcap_get_selectable_fd(defaultPcap.pointer));
      pfds.setShort(EVENTS_OFFSET, POLLIN);
      this.pcap = defaultPcap;
      this.pfds = pfds;
      return this;
    } else {
      throw new IllegalStateException(
          getClass().getSimpleName() + " is not registered or unsupported for current platform.");
    }
  }

  static native int poll(Pointer fds, long nfds, int timeout);

  static native void free(Pointer ptr);

  @Override
  public <A> void events(int timeout, Event<A> event, A attachment) {
    DefaultTimestamp req =
        NativeMappings.PlatformDependent.INSTANCE.pcap_get_required_select_timeout(pcap.pointer);
    if (timeout <= 0 && req != null) {
      timeout = (int) (req.tv_usec.longValue() / 1000L);
    }
    int rc;
    do {
      rc = poll(pfds, 1, timeout);
    } while (rc < 0 && EINTR == com.sun.jna.Native.getLastError());
    if (rc < 0) {
      event.signal(attachment, pcap, Event.OP_ERROR);
    } else if (rc > 0) {
      int revents = pfds.getShort(REVENTS_OFFSET);
      if ((revents & POLLIN) != 0) {
        event.signal(attachment, pcap, Event.OP_READ);
      } else {
        return;
      }
    } else {
      event.signal(attachment, pcap, Event.OP_TIMEOUT);
    }
  }

  @Override
  public void close() throws Exception {
    free(pfds);
  }
}
