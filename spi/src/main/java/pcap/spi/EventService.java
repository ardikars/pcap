package pcap.spi;

import java.util.Iterator;
import java.util.ServiceLoader;
import pcap.spi.annotation.Incubating;
import pcap.spi.exception.ErrorException;

@Incubating
public interface EventService {

  String name();

  @Incubating
  <T extends Pcap> T open(Pcap pcap, Class<T> target);

  class Creator {

    public static EventService create(String name) throws ErrorException {
      ServiceLoader<EventService> loader = ServiceLoader.load(EventService.class);
      Iterator<EventService> iterator = loader.iterator();
      while (iterator.hasNext()) {
        EventService eventService = iterator.next();
        if (eventService.name().equals(name)) {
          return eventService;
        }
      }
      throw new ErrorException("No event service provider implementation for (" + name + ").");
    }
  }
}
