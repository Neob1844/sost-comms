/**
 * SOST Comms — Metadata Minimization
 *
 * Compact header format with shortened field names to reduce
 * envelope overhead while preserving all routing information.
 */

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface MinimalHeader {
  v: 1;
  d: string;    // deal_id
  s: string;    // sender_id
  r: string;    // receiver_id
  t: string;    // msg_type
  n: number;    // seq_no
  ts: number;   // timestamp
  sid: string;  // session_id
}

// ---------------------------------------------------------------------------
// Creation / expansion
// ---------------------------------------------------------------------------

/**
 * Create a minimal header from full-named parameters.
 */
export function createMinimalHeader(params: {
  deal_id: string;
  sender_id: string;
  receiver_id: string;
  msg_type: string;
  seq_no: number;
  session_id: string;
}): MinimalHeader {
  return {
    v: 1,
    d: params.deal_id,
    s: params.sender_id,
    r: params.receiver_id,
    t: params.msg_type,
    n: params.seq_no,
    ts: Date.now(),
    sid: params.session_id,
  };
}

/**
 * Expand a minimal header back to full-named fields.
 */
export function expandHeader(header: MinimalHeader): {
  deal_id: string;
  sender_id: string;
  receiver_id: string;
  msg_type: string;
  seq_no: number;
  timestamp: number;
  session_id: string;
} {
  return {
    deal_id: header.d,
    sender_id: header.s,
    receiver_id: header.r,
    msg_type: header.t,
    seq_no: header.n,
    timestamp: header.ts,
    session_id: header.sid,
  };
}
