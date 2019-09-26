/** This code is licenced under the GPL version 2. */
package pcap.common.util.model;

import pcap.common.util.NamedNumber;

import java.util.HashMap;
import java.util.Map;

/**
 * @author <a href="mailto:contact@ardikars.com">Ardika Rommy Sanjaya</a>
 * @since 1.0.0
 */
public final class HttpStatusCode extends NamedNumber<Integer, HttpStatusCode> {

    private static final Map<Integer, HttpStatusCode> registry
            = new HashMap<Integer, HttpStatusCode>();

    public static final HttpStatusCode NOT_FOUND =
            new HttpStatusCode(404, "Not found.");

    public static final HttpStatusCode OK =
            new HttpStatusCode(20, "OK.");

    public static final HttpStatusCode UNKNOWN =
            new HttpStatusCode(0, "Unknown Http Status Code.");

    public HttpStatusCode(Integer value, String name) {
        super(value, name);
    }

    public static final HttpStatusCode register(final HttpStatusCode httpStatusCode) {
        registry.put(httpStatusCode.getValue(), httpStatusCode);
        return httpStatusCode;
    }

    public static final HttpStatusCode valueOf(final int rawValue) {
        HttpStatusCode httpStatusCode = registry.get(rawValue);
        if (httpStatusCode == null) {
            return UNKNOWN;
        }
        return httpStatusCode;
    }

    static {
        registry.put(NOT_FOUND.getValue(), NOT_FOUND);
        registry.put(OK.getValue(), OK);
        registry.put(UNKNOWN.getValue(), UNKNOWN);
    }

}
