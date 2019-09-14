/** This code is licenced under the GPL version 2. */
package pcap.common.net;

import java.util.regex.Pattern;
import pcap.common.annotation.Inclubating;
import pcap.common.util.Validate;

/** @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a> */
@Inclubating
public final class HostAndPort {

  /** @see <a href="https://www.regextester.com/93928"></a> */
  public static final Pattern DOMAIN_PATTERN =
      Pattern.compile(
          "^(?!:\\/\\/)([a-zA-Z0-9-_]+\\.)*[a-zA-Z0-9][a-zA-Z0-9-_]+\\.[a-zA-Z]{2,11}?$");

  private final String hostName;
  private final InetAddress hostAddress;
  private final int port;

  private HostAndPort(Builder builder) {
    Validate.notIllegalArgument(
        builder.hostName != null, new IllegalArgumentException("Hostname should be not null."));
    Validate.notIllegalArgument(
        builder.hostAddress != null, new IllegalArgumentException("Address sould be not null."));
    Validate.notIllegalArgument(
        builder.port >= 0 && builder.port < 65536, new IllegalArgumentException("Invalid port."));
    if (!DOMAIN_PATTERN.matcher(builder.hostName).matches()) {
      throw new IllegalArgumentException("Invalid hostname.");
    }
    this.hostName = builder.hostName;
    this.hostAddress = builder.hostAddress;
    this.port = builder.port;
  }

  /**
   * Get host name.
   *
   * @return returns host name of this {@code Host} object.
   */
  public String getHostName() {
    return hostName;
  }

  /**
   * Get host address.
   *
   * @return returns host address of this {@code Host} object.
   */
  public InetAddress getHostAddress() {
    return hostAddress;
  }

  /**
   * Get host port.
   *
   * @return returns host port of this {@code Host} object.
   */
  public int getPort() {
    return port;
  }

  /**
   * Returns host name and port with given prefix.
   *
   * @param prefix prefix.
   * @return returns host name and port with given prefix of this {@code Host} object.
   */
  public String hostNameWithPort(String prefix) {
    return Validate.nullPointer(prefix, "") + hostName + ":" + port;
  }

  /**
   * Returns host name and port.
   *
   * @return returns host name and port of this {@code Host} object.
   */
  public String hostNameWithPort() {
    return hostName + ":" + port;
  }

  /**
   * Returns host address with given prefix.
   *
   * @param prefix prefix.
   * @return returns host address with given prefix of this {@code Host} object.
   */
  public String hostAddress(String prefix) {
    return Validate.nullPointer(prefix, "") + getHostAddress().toString();
  }

  /**
   * Returns host address and port with given prefix.
   *
   * @param prefix prefix.
   * @return returns host address and port with given prefix of this {@code Host} object.
   */
  public String hostAddressWithPort(String prefix) {
    return Validate.nullPointer(prefix, "") + hostAddress.toString() + ":" + port;
  }

  /**
   * Returns host address and port.
   *
   * @return returns host address and port of this {@code Host} object.
   */
  public String hostAddressWithPort() {
    return hostAddress.toString() + ":" + port;
  }

  /**
   * Returns host name with given prefix.
   *
   * @param prefix prefix.
   * @return returns host name with given prefix of this {@code Host} object.
   */
  public String hostName(String prefix) {
    return Validate.nullPointer(prefix, "") + getHostName();
  }

  public static Builder builder() {
    return new Builder();
  }

  @Override
  public String toString() {
    return new StringBuilder("Host{")
        .append("hostName='")
        .append(hostName)
        .append('\'')
        .append(", hostAddress=")
        .append(hostAddress)
        .append(", port=")
        .append(port)
        .append('}')
        .toString();
  }

  /** Host builder class. */
  public static final class Builder implements pcap.common.util.Builder<HostAndPort, Void> {

    private String hostName;
    private InetAddress hostAddress;
    private int port;

    /**
     * Host name.
     *
     * @param hostName host name.
     * @return returns this {@code Builder} object.
     */
    public Builder hostName(String hostName) {
      this.hostName = hostName;
      return this;
    }

    /**
     * Host address.
     *
     * @param address host address.
     * @return returns this {@code Builder} object.
     */
    public Builder address(InetAddress address) {
      this.hostAddress = address;
      return this;
    }

    /**
     * Host port.
     *
     * @param port port.
     * @return returns this {@code Builder} object.
     */
    public Builder port(int port) {
      this.port = port;
      return this;
    }

    /**
     * Build {@code Host} object.
     *
     * @return returns {@code Host} object.
     */
    @Override
    public HostAndPort build() {
      return new HostAndPort(this);
    }

    @Override
    public HostAndPort build(Void value) {
      throw new UnsupportedOperationException();
    }
  }
}
