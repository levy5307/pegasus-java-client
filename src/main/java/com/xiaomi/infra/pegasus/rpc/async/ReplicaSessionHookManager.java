package com.xiaomi.infra.pegasus.rpc.async;

import java.util.ArrayList;
import java.util.List;

public class ReplicaSessionHookManager {
  private List<ReplicaSessionHook> hooks = new ArrayList<>();
  private static ReplicaSessionHookManager instance = new ReplicaSessionHookManager();

  public static ReplicaSessionHookManager instance() {
    return instance;
  }

  public void addSecurityHook() {
    SecurityReplicaSessionHook securityHook = new SecurityReplicaSessionHook();
    hooks.add(securityHook);
  }

  public void onConnected(ReplicaSession session) {
    for (ReplicaSessionHook hook : hooks) {
      hook.onConnected(session);
    }
  }

  public boolean onSendMessage(ReplicaSession session, final ReplicaSession.RequestEntry entry) {
    boolean ret = true;
    for (ReplicaSessionHook hook : hooks) {
      ret &= hook.onSendMessage(session, entry);
    }
    return ret;
  }
}
