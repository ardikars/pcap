package pcap.api.jdk7;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;

@RunWith(JUnitPlatform.class)
public class DefaultStatisticsTest {

  @Test
  public void newInstance() {
    DefaultStatistics statistics = new DefaultStatistics();
    statistics.ps_drop = 1;
    statistics.ps_ifdrop = 1;
    statistics.ps_recv = 1;
    statistics.write();
    Assertions.assertEquals(1, statistics.dropped());
    Assertions.assertEquals(1, statistics.droppedByInterface());
    Assertions.assertEquals(1, statistics.received());

    DefaultStatistics fromPointer = new DefaultStatistics(statistics.getPointer());
    Assertions.assertEquals(1, fromPointer.dropped());
    Assertions.assertEquals(1, fromPointer.droppedByInterface());
    Assertions.assertEquals(1, fromPointer.received());
  }
}
