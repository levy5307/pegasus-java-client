package com.xiaomi.infra.pegasus.rpc.async;

import com.xiaomi.infra.pegasus.operator.negotiation_operator;

public class SecurityReplicaSessionHook implements ReplicaSessionHook {
  public void onConnected(ReplicaSession session) {
    Negotiation negotiation = new Negotiation(session);
    negotiation.start();
  }

  public boolean onSendMessage(ReplicaSession session, final ReplicaSession.RequestEntry entry) {
    // tryPendRequest returns false means that the negotiation is succeed now
    return isNegotiationRequest(entry) || !session.tryPendRequest(entry);
  }

  private boolean isNegotiationRequest(final ReplicaSession.RequestEntry entry) {
    return entry.op.getClass().equals(negotiation_operator.class);
  }
}
