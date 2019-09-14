/** This code is licenced under the GPL version 2. */
package pcap.common.util;

import java.util.HashMap;
import java.util.Map;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
public final class DateTimePattern {

  private static String SPACE_DELIMITER = " ";

  public static final String DEFAULT_PATTERN =
      DatePattern.DD_MM_YYYY_WITH_SPACE_AS_DELIMITER.getValue()
          + SPACE_DELIMITER
          + TimePattern.HH_MM_SS_WITH_SPACE_AS_DELIMITER.getValue();

  public static final class DatePattern extends NamedObject<String, DatePattern> {

    public static final DatePattern YYYY_MM_DD_WITH_MINUS_AS_DELIMITER =
        new DatePattern("yyyy-MM-dd", "Year-Month-Day");
    public static final DatePattern DD_MM_YYYY_WITH_MINUS_AS_DELIMITER =
        new DatePattern("dd-MM-yyyy", "Day-Month-Year");

    public static final DatePattern YYYY_MM_WITH_MINUS_AS_DELIMITER =
        new DatePattern("yyyy-MM", "Year-Month");
    public static final DatePattern MM_YYYY_WITH_MINUS_AS_DELIMITER =
        new DatePattern("MM-yyyy", "Month-Year");

    public static final DatePattern YYYY_MM_DD_WITH_SLASH_AS_DELIMITER =
        new DatePattern("yyyy/MM/dd", "Year/Month/Day");
    public static final DatePattern DD_MM_YYYY_WITH_SLASH_AS_DELIMITER =
        new DatePattern("dd/MM/yyyy", "Day/Month/Year");

    public static final DatePattern YYYY_MM_WITH_SLASH_AS_DELIMITER =
        new DatePattern("yyyy/MM", "Year/Month");
    public static final DatePattern MM_YYYY_WITH_SLASH_AS_DELIMITER =
        new DatePattern("MM/yyyy", "Month/Year");

    public static final DatePattern YYYY_MM_DD_WITH_SPACE_AS_DELIMITER =
        new DatePattern("yyyy MM dd", "Year Month Day");
    public static final DatePattern DD_MM_YYYY_WITH_SPACE_AS_DELIMITER =
        new DatePattern("dd MM yyyy", "Day Month Year");

    public static final DatePattern YYYY_MM_WITH_SPACE_AS_DELIMITER =
        new DatePattern("yyyy MM", "Year Month");
    public static final DatePattern MM_YYYY_WITH_SPACE_AS_DELIMITER =
        new DatePattern("MM yyyy", "Month Year");

    private static final Map<String, DatePattern> REGISTRY = new HashMap<String, DatePattern>();

    public DatePattern(String value, String name) {
      super(value, name);
    }

    public static DatePattern register(DatePattern datePattern) {
      REGISTRY.put(datePattern.getValue(), datePattern);
      return datePattern;
    }

    public static DatePattern getDatePattern(String stringDatePattern) {
      return REGISTRY.getOrDefault(stringDatePattern, DD_MM_YYYY_WITH_SPACE_AS_DELIMITER);
    }

    static {
      REGISTRY.put(
          YYYY_MM_DD_WITH_MINUS_AS_DELIMITER.getValue(), YYYY_MM_DD_WITH_MINUS_AS_DELIMITER);
      REGISTRY.put(
          DD_MM_YYYY_WITH_MINUS_AS_DELIMITER.getValue(), DD_MM_YYYY_WITH_MINUS_AS_DELIMITER);
      REGISTRY.put(YYYY_MM_WITH_MINUS_AS_DELIMITER.getValue(), YYYY_MM_WITH_MINUS_AS_DELIMITER);
      REGISTRY.put(MM_YYYY_WITH_MINUS_AS_DELIMITER.getValue(), MM_YYYY_WITH_MINUS_AS_DELIMITER);
      REGISTRY.put(
          YYYY_MM_DD_WITH_SLASH_AS_DELIMITER.getValue(), YYYY_MM_DD_WITH_SLASH_AS_DELIMITER);
      REGISTRY.put(
          DD_MM_YYYY_WITH_SLASH_AS_DELIMITER.getValue(), DD_MM_YYYY_WITH_SLASH_AS_DELIMITER);
      REGISTRY.put(YYYY_MM_WITH_SLASH_AS_DELIMITER.getValue(), YYYY_MM_WITH_SLASH_AS_DELIMITER);
      REGISTRY.put(MM_YYYY_WITH_SLASH_AS_DELIMITER.getValue(), MM_YYYY_WITH_SLASH_AS_DELIMITER);
      REGISTRY.put(
          YYYY_MM_DD_WITH_SPACE_AS_DELIMITER.getValue(), YYYY_MM_DD_WITH_SPACE_AS_DELIMITER);
      REGISTRY.put(
          DD_MM_YYYY_WITH_SPACE_AS_DELIMITER.getValue(), DD_MM_YYYY_WITH_SPACE_AS_DELIMITER);
      REGISTRY.put(YYYY_MM_WITH_SPACE_AS_DELIMITER.getValue(), YYYY_MM_WITH_SPACE_AS_DELIMITER);
      REGISTRY.put(MM_YYYY_WITH_SPACE_AS_DELIMITER.getValue(), MM_YYYY_WITH_SPACE_AS_DELIMITER);
    }
  }

  public static final class TimePattern extends NamedObject<String, TimePattern> {

    public static final TimePattern HH_MM_SS_WITH_COLON_AS_DELIMITER =
        new TimePattern("hh:mm:ss", "Hour:Munite:Second");
    public static final TimePattern HH_MM_WITH_COLON_AS_DELIMITER =
        new TimePattern("hh:mm", "Hour:Munite");
    public static final TimePattern HH_MM_SS_WITH_MINUS_AS_DELIMITER =
        new TimePattern("hh-mm-ss", "Hour-Munite-Second");
    public static final TimePattern HH_MM_WITH_MINUS_AS_DELIMITER =
        new TimePattern("hh-mm", "Hour-Munite");
    public static final TimePattern HH_MM_SS_WITH_SLASH_AS_DELIMITER =
        new TimePattern("hh/mm/ss", "Hour/Munite/Second");
    public static final TimePattern HH_MM_WITH_SLASH_AS_DELIMITER =
        new TimePattern("hh/mm", "Hour/Munite");
    public static final TimePattern HH_MM_SS_WITH_SPACE_AS_DELIMITER =
        new TimePattern("hh mm ss", "Hour Munite Second");
    public static final TimePattern HH_MM_WITH_SPACE_AS_DELIMITER =
        new TimePattern("hh mm", "Hour Munite");

    private static final Map<String, TimePattern> REGISTRY = new HashMap<String, TimePattern>();

    public TimePattern(String value, String name) {
      super(value, name);
    }

    public static TimePattern register(TimePattern timePattern) {
      REGISTRY.put(timePattern.getValue(), timePattern);
      return timePattern;
    }

    public static TimePattern getTimePattern(String stringTimePattern) {
      return REGISTRY.getOrDefault(stringTimePattern, HH_MM_SS_WITH_SPACE_AS_DELIMITER);
    }

    static {
      REGISTRY.put(HH_MM_SS_WITH_COLON_AS_DELIMITER.getValue(), HH_MM_SS_WITH_COLON_AS_DELIMITER);
      REGISTRY.put(HH_MM_WITH_COLON_AS_DELIMITER.getValue(), HH_MM_SS_WITH_COLON_AS_DELIMITER);
      REGISTRY.put(HH_MM_SS_WITH_MINUS_AS_DELIMITER.getValue(), HH_MM_SS_WITH_COLON_AS_DELIMITER);
      REGISTRY.put(HH_MM_WITH_MINUS_AS_DELIMITER.getValue(), HH_MM_SS_WITH_COLON_AS_DELIMITER);
      REGISTRY.put(HH_MM_SS_WITH_SLASH_AS_DELIMITER.getValue(), HH_MM_SS_WITH_COLON_AS_DELIMITER);
      REGISTRY.put(HH_MM_WITH_SLASH_AS_DELIMITER.getValue(), HH_MM_SS_WITH_COLON_AS_DELIMITER);
      REGISTRY.put(HH_MM_SS_WITH_SPACE_AS_DELIMITER.getValue(), HH_MM_SS_WITH_COLON_AS_DELIMITER);
      REGISTRY.put(HH_MM_WITH_SPACE_AS_DELIMITER.getValue(), HH_MM_SS_WITH_COLON_AS_DELIMITER);
    }
  }

  private String pattern;

  private DateTimePattern(Builder builder) {

    Validate.nullPointer(builder, new NullPointerException("DateTime builder should be not null."));

    if (builder.datePattern == null && builder.timePattern == null) {
      this.pattern = DEFAULT_PATTERN;
    } else if (builder.datePattern != null && builder.timePattern != null) {
      if (builder.timeBeforeDate == false) {
        this.pattern =
            builder.datePattern.getValue() + SPACE_DELIMITER + builder.timePattern.getValue();
      } else {
        this.pattern =
            builder.timePattern.getValue() + SPACE_DELIMITER + builder.datePattern.getValue();
      }
    } else if (builder.datePattern != null && builder.timePattern == null) {
      this.pattern = builder.datePattern.getValue();
    } else if (builder.datePattern == null && builder.timePattern != null) {
      this.pattern = builder.timePattern.getValue();
    } else {
      this.pattern = DEFAULT_PATTERN;
    }
  }

  public String getPattern() {
    return pattern;
  }

  public static Builder builder() {
    return new Builder();
  }

  public static class Builder implements pcap.common.util.Builder<DateTimePattern, Void> {

    private DatePattern datePattern;
    private TimePattern timePattern;
    private boolean timeBeforeDate;

    public Builder datePattern(DatePattern datePattern) {
      this.datePattern = datePattern;
      return this;
    }

    public Builder timePattern(TimePattern timePattern) {
      this.timePattern = timePattern;
      return this;
    }

    public Builder timeBeforeDate(boolean timeBeforeDate) {
      this.timeBeforeDate = timeBeforeDate;
      return this;
    }

    @Override
    public DateTimePattern build() {
      return new DateTimePattern(this);
    }

    @Override
    public DateTimePattern build(Void value) {
      throw new UnsupportedOperationException("");
    }
  }
}
