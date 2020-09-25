package com.xiaomi.infra.pegasus.rpc.async;

import com.xiaomi.infra.pegasus.base.blob;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.HashMap;
import javax.security.auth.Subject;
import javax.security.sasl.Sasl;
import javax.security.sasl.SaslClient;
import org.slf4j.Logger;

public class SaslWrapper {
  private static final Logger logger = org.slf4j.LoggerFactory.getLogger(SaslWrapper.class);
  private SaslClient saslClient;
  Subject subject;
  String serviceName;
  String serviceFQDN;
  HashMap<String, Object> props;

  public SaslWrapper(
      Subject subject, String serviceName, String serviceFQDN, HashMap<String, Object> props) {
    this.subject = subject;
    this.serviceName = serviceName;
    this.serviceFQDN = serviceFQDN;
    this.props = props;
  }

  public byte[] init(String[] mechanims) throws PrivilegedActionException {
    return Subject.doAs(
        subject,
        (PrivilegedExceptionAction<byte[]>)
            () -> {
              saslClient =
                  Sasl.createSaslClient(mechanims, null, serviceName, serviceFQDN, props, null);
              return saslClient.getMechanismName().getBytes();
            });
  }

  public blob getInitialResponse() throws PrivilegedActionException {
    return Subject.doAs(
        subject,
        (PrivilegedExceptionAction<blob>)
            () -> {
              if (saslClient.hasInitialResponse()) {
                return new blob(saslClient.evaluateChallenge(new byte[0]));
              } else {
                return new blob(new byte[0]);
              }
            });
  }

  public blob evaluateChallenge(final byte[] data) throws PrivilegedActionException {
    return Subject.doAs(
        subject,
        (PrivilegedExceptionAction<blob>) () -> new blob(saslClient.evaluateChallenge(data)));
  }
}
