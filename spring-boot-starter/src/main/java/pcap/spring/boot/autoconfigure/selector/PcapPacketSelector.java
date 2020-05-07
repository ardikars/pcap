/** This code is licenced under the GPL version 2. */
package pcap.spring.boot.autoconfigure.selector;

import org.springframework.context.annotation.ImportSelector;
import org.springframework.core.annotation.AnnotationAttributes;
import org.springframework.core.type.AnnotationMetadata;
import pcap.spring.boot.autoconfigure.annotation.EnablePcapPacket;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
public class PcapPacketSelector implements ImportSelector {

  @Override
  public String[] selectImports(AnnotationMetadata annotationMetadata) {
    AnnotationAttributes attributes =
        AnnotationAttributes.fromMap(
            annotationMetadata.getAnnotationAttributes(EnablePcapPacket.class.getName(), false));
    if (attributes == null) {
      throw new IllegalStateException();
    }
    return new String[] {"pcap.spring.boot.autoconfigure.PcapPacketAutoConfiguration"};
  }
}
