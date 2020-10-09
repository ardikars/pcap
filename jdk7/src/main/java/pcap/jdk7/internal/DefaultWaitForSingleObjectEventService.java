package pcap.jdk7.internal;

import com.sun.jna.NativeLibrary;
import com.sun.jna.Platform;
import java.nio.channels.SelectionKey;
import pcap.jdk7.EventService;
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
  volatile boolean isOpen;

  public DefaultWaitForSingleObjectEventService() {
    this.pcap = null;
    this.handle = 0L;
    this.isOpen = false;
  }

  static native int WaitForSingleObjectEx(long handle, long dwMilliseconds, int bAlertable);

  @Override
  public EventService open(Pcap pcap) {
    if (REGISTERED) {
      if (!isOpen) {
        DefaultPcap defaultPcap = (DefaultPcap) pcap;
        long handle = NativeMappings.PlatformDependent.INSTANCE.pcap_getevent(defaultPcap.pointer);
        this.pcap = defaultPcap;
        this.handle = handle;
        this.isOpen = true;
      }
      return this;
    } else {
      throw new IllegalStateException(
          getClass().getSimpleName() + " is not registered or unsupported for current platform.");
    }
  }

  @Override
  public int events(int timeout) {
    int rc;
    do {
      rc = WaitForSingleObjectEx(handle, timeout, 1);
    } while (rc < 0 && EINTR == com.sun.jna.Native.getLastError());
    if (rc == 0) {
      int events = 0;
      events |= SelectionKey.OP_READ;
      return events;
    } else if (rc == 0x00000102L) {
      return 0; // timeout
    } else {
      return rc; // error
    }
  }

  @Override
  public void close() throws Exception {
    //
  }
}
