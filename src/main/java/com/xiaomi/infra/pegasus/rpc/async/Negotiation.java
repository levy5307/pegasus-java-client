package com.xiaomi.infra.pegasus.rpc.async;

import com.xiaomi.infra.pegasus.apps.negotiation_request;
import com.xiaomi.infra.pegasus.apps.negotiation_response;
import com.xiaomi.infra.pegasus.apps.negotiation_status;
import com.xiaomi.infra.pegasus.base.blob;
import com.xiaomi.infra.pegasus.base.error_code;
import com.xiaomi.infra.pegasus.operator.negotiation_operator;
import com.xiaomi.infra.pegasus.rpc.ReplicationException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import javax.security.auth.Subject;
import javax.security.sasl.Sasl;
import org.slf4j.Logger;

public class Negotiation {
  private static final Logger logger = org.slf4j.LoggerFactory.getLogger(Negotiation.class);
  // Because negotiation message is always the first rpc sent to pegasus server,
  // which will cost much more time. so we set negotiation timeout to 10s here
  private static final int negotiationTimeoutMS = 10000;
  private static final List<String> expectedMechanisms =
      new ArrayList<>(Collections.singletonList("GSSAPI"));

  private negotiation_status status;
  private ReplicaSession session;
  private SaslWrapper saslWrapper;

  public Negotiation(
      ReplicaSession session, Subject subject, String serviceName, String serviceFQDN) {
    HashMap<String, Object> props = new HashMap<>();
    props.put(Sasl.QOP, "auth");
    saslWrapper = new SaslWrapper(subject, serviceName, serviceFQDN, props);
    this.session = session;
  }

  public void start() {
    status = negotiation_status.SASL_LIST_MECHANISMS;
    send(status, new blob(new byte[0]));
  }

  public void send(negotiation_status status, blob msg) {
    negotiation_request request = new negotiation_request(status, msg);
    negotiation_operator operator = new negotiation_operator(request);
    session.asyncSend(operator, new RecvHandler(operator), negotiationTimeoutMS, false);
  }

  private class RecvHandler implements Runnable {
    private negotiation_operator op;

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

      switch (resp.status) {
        case SASL_LIST_MECHANISMS_RESP:
          on_recv_mechanisms(resp);
          break;
        case SASL_SELECT_MECHANISMS_RESP:
        case SASL_CHALLENGE:
        case SASL_SUCC:
          break;
        default:
          throw new Exception("Received an unexpected response, status " + resp.status);
      }
    }

    void on_recv_mechanisms(negotiation_response response) throws Exception {
      checkStatus(response.status, negotiation_status.SASL_LIST_MECHANISMS_RESP);

      // get match mechanism and init sasl wrapper
      String[] matchMechanism = new String[1];
      matchMechanism[0] = getMatchMechanism(new String(response.msg.data));
      blob msg = new blob(saslWrapper.init(matchMechanism));

      status = negotiation_status.SASL_SELECT_MECHANISMS;
      send(status, msg);
    }

    String getMatchMechanism(String respString) {
      String matchMechanism = new String();
      String[] serverSupportMechanisms = respString.split(",");
      for (String serverSupportMechanism : serverSupportMechanisms) {
        if (expectedMechanisms.contains(serverSupportMechanism)) {
          matchMechanism = serverSupportMechanism;
          break;
        }
      }

      return matchMechanism;
    }

    void checkStatus(negotiation_status status, negotiation_status expected_status)
        throws Exception {
      if (status != expected_status) {
        throw new Exception("status is " + status + " while expect " + expected_status);
      }
    }
  }

  public negotiation_status get_status() {
    return status;
  }
}
