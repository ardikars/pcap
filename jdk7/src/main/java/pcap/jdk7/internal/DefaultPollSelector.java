/*
 * Copyright (c) 2020-2021 Pcap Project
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package pcap.jdk7.internal;

import com.sun.jna.Library;
import com.sun.jna.Native;
import com.sun.jna.Platform;
import com.sun.jna.Structure;
import java.util.*;
import pcap.spi.Selectable;
import pcap.spi.Selector;
import pcap.spi.Timeout;
import pcap.spi.exception.TimeoutException;

class DefaultPollSelector extends AbstractSelector<Integer> {

  private static final short POLLIN = 1;

  private static final int EINTR = 4;

  pollfd[] pfds = new pollfd[0];

  @Override
  public Iterable<Selectable> select(Timeout timeout) throws TimeoutException {
    if (registered.isEmpty()) {
      return Collections.EMPTY_LIST;
    }
    int ts = (int) timeout.microSecond() / 1000;
    int rc;
    do {
      rc = LibC.INSTANCE.poll(pfds, registered.size(), ts);
    } while (rc < 0 && EINTR == Native.getLastError());
    return toIterable(rc, ts);
  }

  @Override
  public Selector register(Selectable pcap) {
    if (!registered.isEmpty()) {
      // Ensure haven't registered yet.
      for (int i = 0; i < registered.entrySet().size(); i++) {
        Iterator<DefaultPcap> iterator = registered.values().iterator();
        while (iterator.hasNext()) {
          DefaultPcap next = iterator.next();
          if (next.equals(pcap)) {
            return this;
          }
        }
      }
      // register new pcap
      DefaultPcap defaultPcap = (DefaultPcap) pcap;
      pollfd[] newPfds = add(defaultPcap, pfds.length + 1);
      for (int i = 0; i < pfds.length; i++) {
        newPfds[i].fd = pfds[i].fd;
        newPfds[i].events = pfds[i].events;
        newPfds[i].revents = pfds[i].revents;
        newPfds[i].write();
      }
      this.pfds = newPfds;
    } else {
      DefaultPcap defaultPcap = (DefaultPcap) pcap;
      this.pfds = add(defaultPcap, 1);
    }
    return this;
  }

  Iterable<Selectable> toIterable(int rc, int timeout) throws TimeoutException {
    if (rc < 0 || rc > registered.size()) {
      return Collections.EMPTY_LIST;
    }
    if (rc == 0) {
      throw new TimeoutException("Timeout: " + timeout + ".");
    }
    final List<Selectable> selected = new ArrayList<Selectable>(rc);
    for (int i = 0; i < registered.size(); i++) {
      pfds[i].read();
      short rEvents = pfds[i].revents;
      if ((rEvents & POLLIN) != 0) {
        selected.add(registered.get(pfds[i].fd));
      }
    }
    return selected;
  }

  private pollfd[] add(DefaultPcap pcap, int size) {
    pollfd[] newPfds = (pollfd[]) (new pollfd().toArray(size));
    int fd = NativeMappings.PLATFORM_DEPENDENT.pcap_get_selectable_fd(pcap.pointer);
    newPfds[pfds.length].fd = fd;
    newPfds[pfds.length].events = POLLIN;
    newPfds[pfds.length].revents = 0;
    newPfds[pfds.length].write();
    pcap.selector = this;
    registered.put(fd, pcap);
    return newPfds;
  }

  @Override
  protected void cancel(DefaultPcap pcap) {
    int fd = NativeMappings.PLATFORM_DEPENDENT.pcap_get_selectable_fd(pcap.pointer);
    for (int i = 0; i < registered.size(); i++) {
      if (pfds[i].fd == fd) {
        if (pfds.length > 1) {
          pollfd[] newPfds = (pollfd[]) (new pollfd().toArray(pfds.length - 1));
          int index = 0;
          for (int j = 0; j < pfds.length; j++) {
            if (j != i) {
              newPfds[index].fd = pfds[index].fd;
              newPfds[index].events = pfds[index].events;
              newPfds[index].revents = pfds[index].revents;
              index++;
            } else {
              registered.remove(fd);
            }
          }
        } else {
          registered.remove(fd);
        }
        break;
      }
    }
  }

  interface LibC extends Library {

    LibC INSTANCE = Native.load(Platform.C_LIBRARY_NAME, LibC.class);

    int poll(pollfd[] fds, int nfds, int timeout);
  }

  public static class pollfd extends Structure {

    public int fd;
    public short events;
    public short revents;

    public pollfd() {}

    @Override
    protected List getFieldOrder() {
      return Arrays.asList( //
          "fd", //
          "events", //
          "revents" //
          );
    }

    @Override
    public boolean equals(Object o) {
      pollfd pollfd = (pollfd) o;
      return fd == pollfd.fd;
    }

    @Override
    public int hashCode() {
      return Objects.hash(fd);
    }
  }
}
