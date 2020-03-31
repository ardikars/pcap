package pcap.spring.boot.autoconfigure.annotation;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import org.springframework.context.annotation.Import;
import pcap.spring.boot.autoconfigure.selector.PcapPacketSelector;

@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.TYPE)
@Import(PcapPacketSelector.class)
public @interface EnablePcapPacket {}
