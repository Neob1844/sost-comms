/**
 * SOST Comms — Replay Guard
 *
 * Sliding-window sequence number tracking + nonce dedup to prevent
 * replayed or reordered messages beyond the acceptable window.
 */

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface AcceptResult {
  accepted: boolean;
  reason?: string;
}

// ---------------------------------------------------------------------------
// Per-session state
// ---------------------------------------------------------------------------

interface SessionState {
  highestSeqNo: number;
  seenSeqNos: Set<number>;
  seenNonces: Set<string>;
}

// ---------------------------------------------------------------------------
// ReplayGuard
// ---------------------------------------------------------------------------

export class ReplayGuard {
  private readonly windowSize: number;
  private readonly sessions = new Map<string, SessionState>();

  constructor(windowSize: number = 100) {
    this.windowSize = windowSize;
  }

  /**
   * Check whether a message should be accepted.
   *
   * Rejects:
   * - Duplicate nonce (exact replay)
   * - Duplicate seq_no (already processed)
   * - seq_no too far behind the sliding window
   */
  accept(sessionId: string, seqNo: number, nonce: string): AcceptResult {
    let state = this.sessions.get(sessionId);
    if (!state) {
      state = { highestSeqNo: -1, seenSeqNos: new Set(), seenNonces: new Set() };
      this.sessions.set(sessionId, state);
    }

    // Duplicate nonce
    if (state.seenNonces.has(nonce)) {
      return { accepted: false, reason: "duplicate_nonce" };
    }

    // Duplicate seq_no
    if (state.seenSeqNos.has(seqNo)) {
      return { accepted: false, reason: "duplicate_seq_no" };
    }

    // Too far behind the window
    if (state.highestSeqNo >= 0 && seqNo < state.highestSeqNo - this.windowSize + 1) {
      return { accepted: false, reason: "behind_window" };
    }

    // Accept
    state.seenNonces.add(nonce);
    state.seenSeqNos.add(seqNo);

    if (seqNo > state.highestSeqNo) {
      state.highestSeqNo = seqNo;

      // Prune seq_nos that have fallen out of the window
      const cutoff = seqNo - this.windowSize + 1;
      if (cutoff > 0) {
        for (const s of state.seenSeqNos) {
          if (s < cutoff) state.seenSeqNos.delete(s);
        }
      }
    }

    return { accepted: true };
  }
}
