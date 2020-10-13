package pcap.jdk7.internal;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;

@RunWith(JUnitPlatform.class)
public class EventServiceTest {

  @Test
  public void newInstance() {
    Assertions.assertTrue(
        EventService.Creator.newInstance(true) instanceof DefaultWaitForSingleObjectEventService);
    Assertions.assertTrue(
        EventService.Creator.newInstance(false) instanceof DefaultPollEventService);
  }
}
