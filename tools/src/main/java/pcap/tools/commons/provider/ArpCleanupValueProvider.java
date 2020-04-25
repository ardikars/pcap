package pcap.tools.commons.provider;

import java.util.Arrays;
import java.util.List;
import org.springframework.core.MethodParameter;
import org.springframework.shell.CompletionContext;
import org.springframework.shell.CompletionProposal;
import org.springframework.shell.standard.ValueProviderSupport;
import org.springframework.stereotype.Component;

@Component
public class ArpCleanupValueProvider extends ValueProviderSupport {

  @Override
  public List<CompletionProposal> complete(
      MethodParameter methodParameter, CompletionContext completionContext, String[] strings) {
    return Arrays.asList(
        new CompletionProposal("own")
            .displayText("own")
            .description("Use own MAC address to send ethernet frame."),
        new CompletionProposal("host")
            .displayText("host")
            .description("Use host MAC address to send ethernet frame."),
        new CompletionProposal("both")
            .displayText("bost")
            .description("Use both own and host mac address to send ethernet frame."));
  }
}
