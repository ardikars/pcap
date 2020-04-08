/** This code is licenced under the GPL version 2. */
package pcap.spring.boot.autoconfigure.experimental.proxy;

import java.io.File;
import java.lang.reflect.Method;
import java.lang.reflect.Parameter;
import pcap.api.*;
import pcap.common.proxy.AbstractInvoker;
import pcap.spi.Interface;
import pcap.spi.Pcap;
import pcap.spi.exception.ErrorException;
import pcap.spi.exception.error.NoSuchDeviceException;
import pcap.spring.boot.autoconfigure.experimental.annotation.Blocking;
import pcap.spring.boot.autoconfigure.experimental.annotation.Direction;
import pcap.spring.boot.autoconfigure.experimental.annotation.Options;
import pcap.spring.boot.autoconfigure.experimental.annotation.Source;

public class PcapCreator extends AbstractInvoker {

  @Override
  public Object invokeImpl(Object proxy, Method method, Object[] args) throws Throwable {
    precondition(method, args);
    Pcap pcap = null;
    Object sourceObject = getSource(method.getParameters(), args);
    if (sourceObject instanceof Interface) {
      Object optionsObject = getOptions(method.getParameters(), args);
      PcapLiveOptions liveOptions = new PcapLiveOptions();
      if (optionsObject != null) {
        if (!(optionsObject instanceof PcapLiveOptions)) {
          throw new IllegalAccessException("Invalid option type");
        }
        liveOptions = (PcapLiveOptions) optionsObject;
      }
      Interface source = (Interface) sourceObject;
      pcap = Pcaps.live(new PcapLive(source, liveOptions));
    } else if (sourceObject instanceof File) {
      Object optionsObject = getOptions(method.getParameters(), args);
      PcapOfflineOptions offlineOptions = new PcapOfflineOptions();
      if (optionsObject != null) {
        if (!(optionsObject instanceof PcapOfflineOptions)) {
          throw new IllegalAccessException("Invalid option type");
        }
        offlineOptions = (PcapOfflineOptions) optionsObject;
      }
      File file = (File) sourceObject;
      pcap = Pcaps.offline(new PcapOffline(file, offlineOptions));
    }
    Blocking blocking = method.getAnnotation(Blocking.class);
    if (blocking != null) {}
    Direction direction = method.getAnnotation(Direction.class);
    if (pcap != null && direction != null) {
      pcap.setDirection(direction.value());
    }
    return null;
  }

  private void precondition(Method method, Object[] args) {}

  private Object getSource(Parameter[] parameters, Object[] args)
      throws NoSuchDeviceException, ErrorException {
    for (int i = 0; i < parameters.length; i++) {
      Source source = parameters[i].getAnnotation(Source.class);
      if (source != null && args[i] != null) {
        if (args[i] instanceof File || args[i] instanceof Interface) {
          return args[i];
        } else {
          throw new IllegalArgumentException("Invalid source type");
        }
      }
    }
    throw new IllegalArgumentException("No pcap source");
  }

  private Object getOptions(Parameter[] parameters, Object[] args) throws RuntimeException {
    for (int i = 0; i < parameters.length; i++) {
      Options options = parameters[i].getAnnotation(Options.class);
      if (options != null) {
        if (args[i] instanceof PcapLiveOptions || args[i] instanceof PcapOfflineOptions) {
          return args[i];
        }
        throw new RuntimeException("Invalid pcap options type");
      }
    }
    return null;
  }
}
