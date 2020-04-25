package pcap.tools.commons.provider;

import java.util.ArrayList;
import java.util.List;
import org.springframework.core.MethodParameter;
import org.springframework.shell.CompletionContext;
import org.springframework.shell.CompletionProposal;
import org.springframework.shell.standard.ValueProviderSupport;
import org.springframework.stereotype.Component;
import pcap.api.Pcaps;
import pcap.spi.exception.ErrorException;

@Component
public class InterfaceValueProvider extends ValueProviderSupport {

  @Override
  public List<CompletionProposal> complete(
      MethodParameter parameter, CompletionContext completionContext, String[] hints) {
    final List<CompletionProposal> COMPLETION_PROPOSALS = new ArrayList<>();
    try {
      Pcaps.lookupInterfaces()
          .forEach(
              anInterface -> {
                CompletionProposal completionProposal =
                    new CompletionProposal(anInterface.name())
                        .displayText(anInterface.name())
                        .description(anInterface.description())
                        .dontQuote(true)
                        .category("Source");
                COMPLETION_PROPOSALS.add(completionProposal);
              });
    } catch (ErrorException e) {
      //
    }
    return COMPLETION_PROPOSALS;
  }
}
