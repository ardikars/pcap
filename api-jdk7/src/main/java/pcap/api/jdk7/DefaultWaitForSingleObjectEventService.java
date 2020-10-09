package pcap.api.jdk7;

import com.sun.jna.NativeLibrary;
import com.sun.jna.Platform;
import pcap.api.Event;
import pcap.api.EventService;
import pcap.spi.Pcap;

class DefaultWaitForSingleObjectEventService implements EventService, AutoCloseable {

  private static final boolean REGISTERED;
  private static final int EINTR = 4;

  static {
    if (Platform.isWindows()) {
      com.sun.jna.Native.register(
          DefaultWaitForSingleObjectEventService.class, NativeLibrary.getInstance("Kernel32"));
      REGISTERED = true;
    } else {
      REGISTERED = false;
    }
  }

  DefaultPcap pcap;
  long handle;

  public DefaultWaitForSingleObjectEventService() {
    this.pcap = null;
    this.handle = 0L;
  }

  static native int WaitForSingleObjectEx(long handle, long dwMilliseconds, int bAlertable);

  @Override
  public EventService open(Pcap pcap) {
    if (REGISTERED) {
      DefaultPcap defaultPcap = (DefaultPcap) pcap;
      long handle = NativeMappings.PlatformDependent.INSTANCE.pcap_getevent(defaultPcap.pointer);
      this.pcap = defaultPcap;
      this.handle = handle;
      return this;
    } else {
      throw new IllegalStateException(
          getClass().getSimpleName() + " is not registered or unsupported for current platform.");
    }
  }

  @Override
  public <A> void events(int timeout, Event<A> event, A attachment) {
    long rc;
    do {
      rc = WaitForSingleObjectEx(handle, timeout, 1);
    } while (rc < 0 && EINTR == com.sun.jna.Native.getLastError());
    if (rc == 0) {
      event.signal(attachment, pcap, Event.OP_READ);
    } else if (rc == 0x00000102L) {
      event.signal(attachment, pcap, Event.OP_TIMEOUT);
    } else {
      event.signal(attachment, pcap, Event.OP_ERROR);
    }
  }

  @Override
  public void close() throws Exception {
    //
  }
}
