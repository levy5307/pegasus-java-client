package com.xiaomi.infra.pegasus.rpc.async;

import com.xiaomi.infra.pegasus.apps.negotiation_request;
import com.xiaomi.infra.pegasus.apps.negotiation_response;
import com.xiaomi.infra.pegasus.apps.negotiation_status;
import com.xiaomi.infra.pegasus.base.blob;
import com.xiaomi.infra.pegasus.base.error_code;
import com.xiaomi.infra.pegasus.operator.negotiation_operator;
import com.xiaomi.infra.pegasus.rpc.ReplicationException;
import org.slf4j.Logger;

public class Negotiation {
  public Negotiation(ReplicaSession session) {
    this.session = session;
  }

  public void start() {
    status = negotiation_status.SASL_LIST_MECHANISMS;
    send(status, new blob(new byte[0]));
  }

  private void send(negotiation_status status, blob msg) {
    negotiation_request request = new negotiation_request(status, msg);
    negotiation_operator operator = new negotiation_operator(request);
    RecvHandler recvHandler = new RecvHandler(operator);

    session.asyncSend(operator, recvHandler, 100, false);
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
        handleResp();
      } catch (Exception e) {
        logger.error(e.toString());
        session.markSessionDisconnect();
      }
    }

    private void handleResp() throws Exception {
      final negotiation_response resp = op.get_response();
      if (resp == null) {
        logger.error("RecvHandler received a null response, abandon it");
        return;
      }

      switch (resp.status) {
        case SASL_LIST_MECHANISMS_RESP:
        case SASL_SELECT_MECHANISMS_RESP:
        case SASL_CHALLENGE:
          break;
        case SASL_SUCC:
          return;
        default:
          throw new Exception("Received an unexpected response, status " + resp.status);
      }
    }
  }

  private ReplicaSession session;
  private negotiation_status status;

  private static final Logger logger = org.slf4j.LoggerFactory.getLogger(Negotiation.class);
}
