package pcap.tools.commons.converter;

import java.io.File;
import org.springframework.core.convert.converter.Converter;
import org.springframework.stereotype.Component;

@Component
public class FileSourceConverter implements Converter<String, File> {

  @Override
  public File convert(String source) {
    File file = new File(source);
    if (file.exists()) {
      return file;
    } else {
      return new InvalidFileSource(source);
    }
  }

  private static class InvalidFileSource extends File {

    private String name;

    public InvalidFileSource(String pathname) {
      super(pathname);
    }

    @Override
    public String toString() {
      return name;
    }
  }
}
