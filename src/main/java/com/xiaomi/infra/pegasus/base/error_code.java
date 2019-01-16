// Copyright (c) 2017, Xiaomi, Inc.  All rights reserved.
// This source code is licensed under the Apache License Version 2.0, which
// can be found in the LICENSE file in the root directory of this source tree.
/**
 * Autogenerated by Thrift
 *
 * DO NOT EDIT UNLESS YOU ARE SURE THAT YOU KNOW WHAT YOU ARE DOING
 */
package com.xiaomi.infra.pegasus.base;

import java.util.List;
import java.util.ArrayList;
import java.util.Map;
import java.util.HashMap;
import java.util.EnumMap;
import java.util.Set;
import java.util.HashSet;
import java.util.EnumSet;
import java.util.Collections;
import java.util.BitSet;
import java.nio.ByteBuffer;
import java.util.Arrays;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.xiaomi.infra.pegasus.thrift.*;
import com.xiaomi.infra.pegasus.thrift.async.*;
import com.xiaomi.infra.pegasus.thrift.meta_data.*;
import com.xiaomi.infra.pegasus.thrift.transport.*;
import com.xiaomi.infra.pegasus.thrift.protocol.*;

public class error_code implements TBase<error_code, error_code._Fields>, java.io.Serializable, Cloneable {
  private static final TStruct STRUCT_DESC = new TStruct("error_code");
  public enum error_types {
      // ERROR_CODE copy from rDSN
      ERR_OK,

      ERR_UNKNOWN,
      ERR_SERVICE_NOT_FOUND,
      ERR_SERVICE_ALREADY_RUNNING,
      ERR_IO_PENDING,
      ERR_TIMEOUT,
      ERR_SERVICE_NOT_ACTIVE,
      ERR_BUSY,
      ERR_NETWORK_INIT_FAILED,
      ERR_FORWARD_TO_OTHERS,
      ERR_OBJECT_NOT_FOUND,

      ERR_HANDLER_NOT_FOUND,
      ERR_LEARN_FILE_FAILED,
      ERR_GET_LEARN_STATE_FAILED,
      ERR_INVALID_VERSION,
      ERR_INVALID_PARAMETERS,
      ERR_CAPACITY_EXCEEDED,
      ERR_INVALID_STATE,
      ERR_INACTIVE_STATE,
      ERR_NOT_ENOUGH_MEMBER,
      ERR_FILE_OPERATION_FAILED,

      ERR_HANDLE_EOF,
      ERR_WRONG_CHECKSUM,
      ERR_INVALID_DATA,
      ERR_INVALID_HANDLE,
      ERR_INCOMPLETE_DATA,
      ERR_VERSION_OUTDATED,
      ERR_PATH_NOT_FOUND,
      ERR_PATH_ALREADY_EXIST,
      ERR_ADDRESS_ALREADY_USED,
      ERR_STATE_FREEZED,

      ERR_LOCAL_APP_FAILURE,
      ERR_BIND_IOCP_FAILED,
      ERR_NETWORK_START_FAILED,
      ERR_NOT_IMPLEMENTED,
      ERR_CHECKPOINT_FAILED,
      ERR_WRONG_TIMING,
      ERR_NO_NEED_OPERATE,
      ERR_CORRUPTION,
      ERR_TRY_AGAIN,
      ERR_CLUSTER_NOT_FOUND,

      ERR_CLUSTER_ALREADY_EXIST,
      ERR_SERVICE_ALREADY_EXIST,
      ERR_INJECTED,
      ERR_REPLICATION_FAILURE,
      ERR_APP_EXIST,
      ERR_APP_NOT_EXIST,
      ERR_BUSY_CREATING,
      ERR_BUSY_DROPPING,
      ERR_NETWORK_FAILURE,
      ERR_UNDER_RECOVERY,

      ERR_LEARNER_NOT_FOUND,
      ERR_OPERATION_DISABLED,
      ERR_EXPIRED,
      ERR_LOCK_ALREADY_EXIST,
      ERR_HOLD_BY_OTHERS,
      ERR_RECURSIVE_LOCK,
      ERR_NO_OWNER,
      ERR_NODE_ALREADY_EXIST,
      ERR_INCONSISTENT_STATE,
      ERR_ARRAY_INDEX_OUT_OF_RANGE,

      ERR_DIR_NOT_EMPTY,
      ERR_FS_INTERNAL,
      ERR_IGNORE_BAD_DATA,
      ERR_APP_DROPPED,
      ERR_MOCK_INTERNAL,
      ERR_ZOOKEEPER_OPERATION,

      ERR_AUTH_NEGO_FAILED,

      ERR_UNAUTHENTICATED,
      ERR_ACL_DENY,
      //ERROR_CODE defined by client
      ERR_SESSION_RESET,
  };
  public error_types errno;

  /** The set of fields this struct contains, along with convenience methods for finding and manipulating them. */
  public enum _Fields implements TFieldIdEnum {
;

    private static final Map<String, _Fields> byName = new HashMap<String, _Fields>();

    static {
      for (_Fields field : EnumSet.allOf(_Fields.class)) {
        byName.put(field.getFieldName(), field);
      }
    }

    /**
     * Find the _Fields constant that matches fieldId, or null if its not found.
     */
    public static _Fields findByThriftId(int fieldId) {
      switch(fieldId) {
        default:
          return null;
      }
    }

    /**
     * Find the _Fields constant that matches fieldId, throwing an exception
     * if it is not found.
     */
    public static _Fields findByThriftIdOrThrow(int fieldId) {
      _Fields fields = findByThriftId(fieldId);
      if (fields == null) throw new IllegalArgumentException("Field " + fieldId + " doesn't exist!");
      return fields;
    }

    /**
     * Find the _Fields constant that matches name, or null if its not found.
     */
    public static _Fields findByName(String name) {
      return byName.get(name);
    }

    private final short _thriftId;
    private final String _fieldName;

    _Fields(short thriftId, String fieldName) {
      _thriftId = thriftId;
      _fieldName = fieldName;
    }

    public short getThriftFieldId() {
      return _thriftId;
    }

    public String getFieldName() {
      return _fieldName;
    }
  }
  public static final Map<_Fields, FieldMetaData> metaDataMap;
  static {
    Map<_Fields, FieldMetaData> tmpMap = new EnumMap<_Fields, FieldMetaData>(_Fields.class);
    metaDataMap = Collections.unmodifiableMap(tmpMap);
    FieldMetaData.addStructMetaDataMap(error_code.class, metaDataMap);
  }

  public error_code() {
    errno = error_types.ERR_UNKNOWN;
  }

  public error_code(error_types err_enum_type) {
    errno = err_enum_type;
  }
  
  public void set_error_type(error_types err_enum_type) {
      errno = err_enum_type;
  }

  public error_code(String message) {
      errno = error_types.valueOf(message);
  }

  /**
   * Performs a deep copy on <i>other</i>.
   */
  public error_code(error_code other) {
    this.errno = other.errno;
  }

  public error_code deepCopy() {
    return new error_code(this);
  }

  @Override
  public void clear() {
  }

  public void setFieldValue(_Fields field, Object value) {
    switch (field) {
    }
  }

  public Object getFieldValue(_Fields field) {
    switch (field) {
    }
    throw new IllegalStateException();
  }

  /** Returns true if field corresponding to fieldID is set (has been asigned a value) and false otherwise */
  public boolean isSet(_Fields field) {
    if (field == null) {
      throw new IllegalArgumentException();
    }

    switch (field) {
    }
    throw new IllegalStateException();
  }

  @Override
  public boolean equals(Object that) {
      if (that == null)
          return false;
      if (that instanceof error_code)
          return this.equals((error_code) that);
      return false;
  }

  public boolean equals(error_code that) {
      if (that == null)
          return false;
      return this.errno.equals(that.errno);
  }

  @Override
  public int hashCode() {
    return this.errno.hashCode();
  }

  public int compareTo(error_code other) {
      if (!getClass().equals(other.getClass())) {
          return getClass().getName().compareTo(other.getClass().getName());
      }
      return this.errno.compareTo(other.errno);
  }


  public _Fields fieldForId(int fieldId) {
    return _Fields.findByThriftId(fieldId);
  }

  public void read(TProtocol iprot) throws TException {
    String err_message = iprot.readString();
    errno = error_types.valueOf(err_message);
    // check for required fields of primitive type, which can't be checked in the validate method
    validate();
  }

  public void write(TProtocol oprot) throws TException {
    validate();
    oprot.writeString(String.valueOf(errno));
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder("error_code(");
    sb.append(String.valueOf(errno));
    sb.append(")");
    return sb.toString();
  }

  public void validate() throws TException {
    // check for required fields
  }

}

