/*
 * Copyright (c) 2020 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.jdk7.internal;

import com.sun.jna.*;
import java.lang.ref.PhantomReference;
import java.lang.ref.Reference;
import java.lang.ref.ReferenceQueue;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import pcap.spi.Pcap;
import pcap.spi.annotation.Async;

class DefaultPollEventService extends AbstractEventService implements InvocationHandler {

  static final Set<Reference<DefaultPollEventService>> REFS =
      Collections.synchronizedSet(new HashSet<Reference<DefaultPollEventService>>());

  static final ReferenceQueue<DefaultPollEventService> RQ =
      new ReferenceQueue<DefaultPollEventService>();

  private static final short POLLIN = 0x1;
  private static final int FD_OFFSET = 0;
  private static final int EVENTS_OFFSET = FD_OFFSET + 4;
  private static final int REVENTS_OFFSET = EVENTS_OFFSET + 2;

  static {
    register(Platform.isWindows());
  }

  final Pointer pfds;

  DefaultPollEventService() {
    super(null);
    this.pfds = null;
  }

  DefaultPollEventService(DefaultPcap pcap, Pointer pfds) {
    super(pcap);
    this.pfds = pfds;
    PollReference reference = new PollReference(pfds, this, RQ);
    REFS.add(reference);
    PollReference ref;
    while ((ref = (PollReference) RQ.poll()) != null) {
      Native.free(Pointer.nativeValue(ref.pfds));
    }
  }

  static void register(boolean isWindows) {
    if (!isWindows) {
      com.sun.jna.Native.register(
          DefaultPollEventService.class, NativeLibrary.getInstance(Platform.C_LIBRARY_NAME));
    }
  }

  static native int poll(Pointer fds, long nfds, int timeout);

  static int normalizeTimeout(int timeout, Pointer timestamp) {
    if (timeout <= 0 && timestamp != null) {
      timeout =
          (int) (timestamp.getNativeLong(DefaultTimestamp.TV_USEC_OFFSET).longValue() / 1000L);
    }
    return timeout;
  }

  static int normalizeREvents(int rc, Pointer pfds) {
    int status;
    if (rc > 0) {
      int revents = pfds.getShort(REVENTS_OFFSET);
      if ((revents & POLLIN) != POLLIN) {
        status = -1;
      } else {
        status = 0;
      }
    } else if (rc < 0) {
      status = -1;
    } else {
      status = 1;
    }
    return status;
  }

  @Override
  public <T extends Pcap> T open(Pcap pcap, Class<T> target) {
    DefaultPcap defaultPcap = (DefaultPcap) pcap;
    Pointer pfds = new Memory(8);
    pfds.setInt(
        FD_OFFSET, NativeMappings.PLATFORM_DEPENDENT.pcap_get_selectable_fd(defaultPcap.pointer));
    pfds.setShort(EVENTS_OFFSET, POLLIN);
    return newProxy(target, new DefaultPollEventService(defaultPcap, pfds));
  }

  @Override
  public Object invoke(Object proxy, Method proxyMethod, Object[] args) throws Throwable {
    Method pcapMethod =
        pcap.getClass().getDeclaredMethod(proxyMethod.getName(), proxyMethod.getParameterTypes());
    Async async = getAsync(proxyMethod);
    if (async == null) {
      return invoke(pcapMethod, args);
    }
    int timeout =
        normalizeTimeout(
            async.timeout(), UnixMapping.pcap_get_required_select_timeout(pcap.pointer));
    int rc;
    do {
      rc = poll(pfds, 1, timeout);
    } while (rc < 0 && EINTR == com.sun.jna.Native.getLastError());
    return invokeOnReady(normalizeREvents(rc, pfds), 0, 1, pcapMethod, args);
  }

  static final class UnixMapping {

    static {
      com.sun.jna.Native.register(
          UnixMapping.class,
          NativeLibrary.getInstance(NativeMappings.libName(Platform.isWindows())));
    }

    private UnixMapping() {}

    static native Pointer pcap_get_required_select_timeout(Pointer p);
  }

  static final class PollReference extends PhantomReference<DefaultPollEventService> {

    final Pointer pfds;

    PollReference(
        Pointer pfds,
        DefaultPollEventService referent,
        ReferenceQueue<? super DefaultPollEventService> q) {
      super(referent, q);
      this.pfds = pfds;
    }
  }
}
