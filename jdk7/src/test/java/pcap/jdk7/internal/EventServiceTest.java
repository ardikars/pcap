package pcap.jdk7.internal;

import com.sun.jna.Platform;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;

@RunWith(JUnitPlatform.class)
public class EventServiceTest {

  @Test
  void newInstance() {
    if (Platform.isWindows()) {
      Assertions.assertTrue(
          EventService.Creator.newInstance(true) instanceof DefaultWaitForSingleObjectEventService);
    } else {
      Assertions.assertTrue(
          EventService.Creator.newInstance(false) instanceof DefaultPollEventService);
    }
  }
}
