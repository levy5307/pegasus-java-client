package com.xiaomi.infra.pegasus.rpc.interceptor;

import com.sun.security.auth.callback.TextCallbackHandler;
import com.xiaomi.infra.pegasus.client.ClientOptions;
import com.xiaomi.infra.pegasus.rpc.async.Negotiation;
import com.xiaomi.infra.pegasus.rpc.async.ReplicaSession;
import java.util.HashMap;
import java.util.Map;
import javax.security.auth.Subject;
import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import org.slf4j.Logger;

public class SecurityReplicaSessionInterceptor implements ReplicaSessionInterceptor {
  private static final Logger logger =
      org.slf4j.LoggerFactory.getLogger(SecurityReplicaSessionInterceptor.class);

  private String serviceName;
  private String serviceFqdn;

  // JAAS internal class, Ref:
  // https://docs.oracle.com/javase/7/docs/technotes/guides/security/jaas/JAASRefGuide.html
  //
  // To authorize access to resources, applications first need to authenticate the source of the
  // request. The JAAS framework defines the term subject to represent the source of a request. A
  // subject may be any entity, such as a person or a service
  private Subject subject;
  // The LoginContext class provides the basic methods used to authenticate subjects, and provides a
  // way to develop an application independent of the underlying authentication technology
  private LoginContext loginContext;

  public SecurityReplicaSessionInterceptor(ClientOptions options) throws IllegalArgumentException {
    this.serviceName = options.getServiceName();
    this.serviceFqdn = options.getServiceFQDN();

    try {
      // actual authentication: authenticate the Subject
      subject = new Subject();
      loginContext =
          new LoginContext(
              "pegasus-client",
              subject,
              new TextCallbackHandler(),
              getLoginContextConfiguration(options));
      loginContext.login();
    } catch (LoginException le) {
      throw new IllegalArgumentException("login failed", le);
    }

    logger.info("login succeed, as user {}", subject.getPrincipals().toString());
  }

  public void onConnected(ReplicaSession session) {
    Negotiation negotiation = new Negotiation(session, subject, serviceName, serviceFqdn);
    negotiation.start();
  }

  private Configuration getLoginContextConfiguration(ClientOptions clientOptions) {
    return new Configuration() {
      @Override
      public AppConfigurationEntry[] getAppConfigurationEntry(String name) {
        Map<String, String> options = new HashMap<>();
        // TGT is obtained from the ticket cache.
        options.put("useTicketCache", "true");
        // get the principal's key from the the keytab
        options.put("useKeyTab", "true");
        // renew the TGT
        options.put("renewTGT", "true");
        // keytab or the principal's key to be stored in the Subject's private credentials.
        options.put("storeKey", "true");
        // the file name of the keytab to get principal's secret key.
        options.put("keyTab", clientOptions.getKeyTab());
        // the name of the principal that should be used
        options.put("principal", clientOptions.getPrincipal());

        return new AppConfigurationEntry[] {
          new AppConfigurationEntry(
              "com.sun.security.auth.module.Krb5LoginModule",
              AppConfigurationEntry.LoginModuleControlFlag.REQUIRED,
              options)
        };
      }
    };
  }
}
