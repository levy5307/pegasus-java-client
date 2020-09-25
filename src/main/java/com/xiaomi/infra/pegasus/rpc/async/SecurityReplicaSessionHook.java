package com.xiaomi.infra.pegasus.rpc.async;

import com.sun.security.auth.callback.TextCallbackHandler;
import com.xiaomi.infra.pegasus.client.ClientOptions;
import com.xiaomi.infra.pegasus.operator.negotiation_operator;
import java.util.HashMap;
import java.util.Map;
import javax.security.auth.Subject;
import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import org.slf4j.Logger;

public class SecurityReplicaSessionHook implements ReplicaSessionHook {
  private static final Logger logger =
      org.slf4j.LoggerFactory.getLogger(SecurityReplicaSessionHook.class);

  private String serviceName;
  private String serviceFqdn;
  private Subject subject;
  private LoginContext loginContext;

  public SecurityReplicaSessionHook(ClientOptions opts) {
    this.serviceName = opts.getServiceName();
    this.serviceFqdn = opts.getServiceFQDN();

    try {
      loginContext =
          new LoginContext(
              "pegasus-client", new Subject(), new TextCallbackHandler(), getConfiguration(opts));
      loginContext.login();

      subject = loginContext.getSubject();
      if (subject == null) {
        throw new LoginException("subject is null");
      }
    } catch (LoginException le) {
      logger.error("login failed", le);
      System.exit(-1);
    }

    logger.info("login succeed, as user {}", subject.getPrincipals().toString());
  }

  public void onConnected(ReplicaSession session) {
    Negotiation negotiation = new Negotiation(session, subject, serviceName, serviceFqdn);
    negotiation.start();
  }

  public boolean onSendMessage(ReplicaSession session, final ReplicaSession.RequestEntry entry) {
    // tryPendRequest returns false means that the negotiation is succeed now
    return isNegotiationRequest(entry) || !session.tryPendRequest(entry);
  }

  private boolean isNegotiationRequest(final ReplicaSession.RequestEntry entry) {
    return entry.op.getClass().equals(negotiation_operator.class);
  }

  private Configuration getConfiguration(ClientOptions clientOptions) {
    return new Configuration() {
      @Override
      public AppConfigurationEntry[] getAppConfigurationEntry(String name) {
        Map<String, String> options = new HashMap<>();
        options.put("useTicketCache", "true");
        options.put("renewTGT", "true");
        options.put("useKeyTab", "true");
        options.put("renewTGT", "true");
        options.put("storeKey", "true");
        options.put("keyTab", clientOptions.getKeyTab());
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
