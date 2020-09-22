package com.xiaomi.infra.pegasus.rpc.async;

import com.xiaomi.infra.pegasus.apps.negotiation_request;
import com.xiaomi.infra.pegasus.apps.negotiation_response;
import com.xiaomi.infra.pegasus.apps.negotiation_status;
import com.xiaomi.infra.pegasus.base.blob;
import com.xiaomi.infra.pegasus.base.error_code;
import com.xiaomi.infra.pegasus.operator.negotiation_operator;
import com.xiaomi.infra.pegasus.rpc.ReplicationException;

import java.security.PrivilegedExceptionAction;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import javax.security.auth.Subject;
import javax.security.sasl.Sasl;
import javax.security.sasl.SaslClient;

import org.slf4j.Logger;

public class Negotiation {
  private static final Logger logger = org.slf4j.LoggerFactory.getLogger(Negotiation.class);
  private static final int rpcTimeout = 5000;
  private static final List<String> expectedMechanisms =
          new ArrayList<>(Collections.singletonList("GSSAPI"));

  private negotiation_status status;
  private ReplicaSession session;
  private String serviceName; // used for SASL authentication
  private String serviceFqdn; // name used for SASL authentication
  private final HashMap<String, Object> props = new HashMap<String, Object>();
  private final Subject subject;
  private SaslClient saslClient;

  public Negotiation(
      ReplicaSession session, Subject subject, String serviceName, String serviceFqdn) {
    this.session = session;
    this.subject = subject;
    this.serviceName = serviceName;
    this.serviceFqdn = serviceFqdn;
    this.props.put(Sasl.QOP, "auth");
  }

  public void start() {
    status = negotiation_status.SASL_LIST_MECHANISMS;
    negotiation_request request = new negotiation_request(status, new blob(new byte[0]));
    send(request);
  }

  private void send(negotiation_request request) {
    negotiation_operator operator = new negotiation_operator(request);
    session.asyncSend(operator, new RecvHandler(operator), rpcTimeout, false);
  }

  private class Action implements PrivilegedExceptionAction {
    @Override
    public Object run() throws Exception {
      return null;
    }
  }

  private class RecvHandler implements Runnable {
    negotiation_operator op;

    RecvHandler(negotiation_operator op) {
      this.op = op;
    }

    @Override
    public void run() {
      try {
        if (op.rpc_error.errno != error_code.error_types.ERR_OK) {
          throw new ReplicationException(op.rpc_error.errno);
        }
        handleResponse();
      } catch (Exception e) {
        logger.error("Negotiation failed", e);
      }
    }

    private void handleResponse() throws Exception {
      final negotiation_response resp = op.get_response();
      if (resp == null) {
        throw new Exception("RecvHandler received a null response, abandon it");
      }

      negotiation_request request = new negotiation_request();
      switch (resp.status) {
        case SASL_LIST_MECHANISMS_RESP:
          Subject.doAs(
                  subject,
                  new Action() {
                    public Object run() throws Exception {
                      String[] mechanisms = new String[expectedMechanisms.size()];
                      expectedMechanisms.toArray(mechanisms);
                      saslClient =
                              Sasl.createSaslClient(
                                      mechanisms, null, serviceName, serviceFqdn, props, null);
                      logger.info("Select mechanism: {}", saslClient.getMechanismName());
                      request.status = negotiation_status.SASL_SELECT_MECHANISMS;
                      request.msg = new blob(saslClient.getMechanismName().getBytes());
                      return null;
                    }
                  });
        case SASL_SELECT_MECHANISMS_RESP:
        case SASL_CHALLENGE:
        case SASL_SUCC:
          break;
        default:
          throw new Exception("Received an unexpected response, status " + resp.status);
      }

      send(request);
    }

    boolean checkStatus(negotiation_status status, negotiation_status expected_status) {
      if (status != negotiation_status.SASL_LIST_MECHANISMS) {
          logger.warn("get message({}), while expect({})", status, expected_status);
          return false;
      }

      return true;
    }
  }

  public negotiation_status get_status() {
    return status;
  }
}
