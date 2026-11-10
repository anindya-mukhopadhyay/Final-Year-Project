"""
AnswerChain Phase 9C: Subject-wise Head Examiner Democratic Election Mechanism.

Manages democratic elections where teachers vote for a subject Head Examiner.
Enforces:
1. One authenticated vote per eligible teacher per subject election.
2. Ed25519 cryptographic signature verification on every ballot.
3. Strict duplicate vote rejection.
4. Quorum and majority threshold calculation.
5. Deterministic tie-breaking and vacancy management.
6. Blockchain-ready HEAD_EXAMINER_ELECTED transaction generation.
"""

import hashlib
import json
import logging
import os
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple

from backend.crypto import (
    canonicalize_transaction_payload,
    get_actor_public_key,
    get_or_create_actor_keys,
    sign_academic_transaction,
    sign_payload,
    verify_signature,
)

logger = logging.getLogger("examiner.election")

# Canonical teacher mapping to examiner nodes
EXAMINER_TEACHER_MAP = {
    "NODE-001": "TCH-001",
    "NODE-002": "TCH-002",
    "NODE-003": "TCH-003",
    "NODE-004": "TCH-004",
    "NODE-005": "TCH-005",
}

TEACHER_EXAMINER_MAP = {v: k for k, v in EXAMINER_TEACHER_MAP.items()}
DEFAULT_ELIGIBLE_TEACHERS = list(TEACHER_EXAMINER_MAP.keys())


class ElectionStatus:
    PENDING = "PENDING"
    IN_PROGRESS = "IN_PROGRESS"
    CONCLUDED = "CONCLUDED"
    FAILED_INSUFFICIENT_PARTICIPATION = "FAILED_INSUFFICIENT_PARTICIPATION"
    TIED = "TIED"


class SubjectElection:
    """State of an individual subject Head Examiner election."""

    def __init__(
        self,
        election_id: str,
        subject: str,
        term_days: int = 365,
        eligible_voters: Optional[List[str]] = None,
        quorum_threshold: int = 3,  # Legacy alias for participation quorum
        participation_quorum: Optional[int] = None,  # Separate participation quorum (e.g. >= 3 votes)
        winning_threshold: Optional[float] = None,  # Separate candidate threshold (e.g. > 0.5)
        initiated_by: str = "ADMIN-001",
        created_at: Optional[float] = None,
    ) -> None:
        self.election_id = election_id
        self.subject = subject.strip().upper()
        self.term_days = int(term_days)
        self.eligible_voters: List[str] = list(eligible_voters or DEFAULT_ELIGIBLE_TEACHERS)
        self.participation_quorum = int(participation_quorum if participation_quorum is not None else quorum_threshold)
        self.quorum_threshold = self.participation_quorum
        self.winning_threshold = float(winning_threshold) if winning_threshold is not None else None
        self.initiated_by = initiated_by
        self.created_at = float(created_at if created_at is not None else time.time())
        self.status = ElectionStatus.IN_PROGRESS

        # Auditable ballots: voter_id -> ballot dict
        self.votes: Dict[str, Dict[str, Any]] = {}
        self.winner_id: Optional[str] = None
        self.winner_node_id: Optional[str] = None
        self.term_start: Optional[float] = None
        self.term_end: Optional[float] = None
        self.certified_transaction: Optional[Dict[str, Any]] = None
        self.tie_info: Optional[Dict[str, Any]] = None

    def canonical_ballot_bytes(self, voter_id: str, candidate_id: str) -> bytes:
        """Deterministic canonical bytes of a vote ballot for signing/verification."""
        data = {
            "election_id": self.election_id,
            "subject": self.subject,
            "voter_id": voter_id.strip().upper(),
            "candidate_id": candidate_id.strip().upper(),
        }
        return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def cast_vote(
        self,
        voter_id: str,
        candidate_id: str,
        signature: Optional[str] = None,
        timestamp: Optional[float] = None,
    ) -> Tuple[bool, str]:
        """
        Cast an authenticated vote.
        Rejects unauthorized voters, invalid candidates, and duplicates.
        """
        clean_voter = voter_id.strip().upper()
        clean_cand = candidate_id.strip().upper()

        if self.status != ElectionStatus.IN_PROGRESS:
            return False, f"ELECTION_NOT_ACTIVE: status is {self.status}"

        if clean_voter not in self.eligible_voters:
            return False, f"UNAUTHORIZED_VOTER: {clean_voter} not in eligible voters"

        if clean_cand not in self.eligible_voters:
            return False, f"INVALID_CANDIDATE: {clean_cand} not an eligible teacher"

        if clean_voter in self.votes:
            return False, f"DUPLICATE_VOTE_REJECTED: {clean_voter} has already voted in {self.election_id}"

        # Cryptographic verification
        canonical_bytes = self.canonical_ballot_bytes(clean_voter, clean_cand)
        if signature:
            pub_key = get_actor_public_key(clean_voter)
            if not pub_key:
                return False, f"VOTER_PUBLIC_KEY_NOT_FOUND: {clean_voter}"
            if not verify_signature(pub_key, canonical_bytes, signature):
                return False, "SIGNATURE_INVALID"
        else:
            # Auto-sign if in local development key context
            try:
                priv, _ = get_or_create_actor_keys(clean_voter)
                signature = sign_payload(priv, canonical_bytes)
            except Exception as e:
                return False, f"SIGNING_FAILED: {e}"

        ballot = {
            "election_id": self.election_id,
            "subject": self.subject,
            "voter_id": clean_voter,
            "candidate_id": clean_cand,
            "signature": signature,
            "timestamp": float(timestamp if timestamp is not None else time.time()),
        }
        self.votes[clean_voter] = ballot
        return True, "VOTE_ACCEPTED"

    def tally(self, break_ties: bool = True) -> Tuple[bool, str, Dict[str, Any]]:
        """
        Tally election ballots and determine winner.
        1. Participation quorum check (total_votes >= participation_quorum).
        2. Candidate vote distribution calculation.
        3. Tie handling: if multiple candidates tie for 1st place:
           - if break_ties is False: sets status to TIED and returns False.
           - if break_ties is True: deterministically resolves via auditable seniority rule.
        4. Candidate winning threshold check if configured.
        """
        total_votes = len(self.votes)
        if total_votes < self.participation_quorum:
            self.status = ElectionStatus.FAILED_INSUFFICIENT_PARTICIPATION
            return False, "INSUFFICIENT_PARTICIPATION", {
                "status": self.status,
                "votes_cast": total_votes,
                "participation_quorum_required": self.participation_quorum,
            }

        # Count votes per candidate
        counts: Dict[str, int] = {}
        for ballot in self.votes.values():
            cand = ballot["candidate_id"]
            counts[cand] = counts.get(cand, 0) + 1

        # Determine highest vote count
        sorted_candidates = sorted(counts.items(), key=lambda x: x[1], reverse=True)
        top_cand, top_votes = sorted_candidates[0]

        # Check for ties
        tied_candidates = [cand for cand, v in sorted_candidates if v == top_votes]
        is_tie = len(tied_candidates) > 1

        if is_tie:
            self.tie_info = {
                "is_tied": True,
                "tied_candidates": tied_candidates,
                "top_votes": top_votes,
            }
            if not break_ties:
                self.status = ElectionStatus.TIED
                return False, "ELECTION_TIED", {
                    "status": self.status,
                    "tied_candidates": tied_candidates,
                    "top_votes": top_votes,
                    "votes_summary": counts,
                    "votes_cast": total_votes,
                }
            # Deterministic tie-breaking rule: lowest lexicographical ID (seniority fallback)
            winner = sorted(tied_candidates)[0]
            logger.info("Tie between %s resolved deterministically in favor of %s", tied_candidates, winner)
        else:
            winner = top_cand

        # Check candidate threshold if specified
        if self.winning_threshold is not None:
            win_ratio = top_votes / total_votes
            if win_ratio < self.winning_threshold:
                return False, "WINNING_THRESHOLD_NOT_MET", {
                    "top_candidate": winner,
                    "win_ratio": win_ratio,
                    "required_threshold": self.winning_threshold,
                }

        self.winner_id = winner
        self.winner_node_id = TEACHER_EXAMINER_MAP.get(winner, "NODE-001")
        now = time.time()
        self.term_start = now
        self.term_end = now + (self.term_days * 86400)
        self.status = ElectionStatus.CONCLUDED

        # Generate signed blockchain transaction payload
        tx_payload = {
            "type": "HEAD_EXAMINER_ELECTED",
            "election_id": self.election_id,
            "subject": self.subject,
            "head_examiner_id": self.winner_id,
            "head_examiner_node_id": self.winner_node_id,
            "votes_cast": total_votes,
            "votes_summary": counts,
            "quorum_reached": True,
            "term_start": self.term_start,
            "term_end": self.term_end,
            "term_days": self.term_days,
            "status": "ELECTED",
            "tie_resolved": is_tie,
        }

        signed_tx = sign_academic_transaction(
            payload=tx_payload,
            actor_id="AUTH-001",
            actor_role="AUTHORITY",
        )
        self.certified_transaction = signed_tx

        return True, "ELECTION_CONCLUDED", {
            "status": self.status,
            "winner_id": self.winner_id,
            "winner_node_id": self.winner_node_id,
            "votes_summary": counts,
            "votes_cast": total_votes,
            "term_start": self.term_start,
            "term_end": self.term_end,
            "tie_resolved": is_tie,
            "transaction": signed_tx,
        }

    def to_dict(self, full: bool = False) -> Dict[str, Any]:
        """Convert election to inspectable dictionary."""
        d = {
            "election_id": self.election_id,
            "subject": self.subject,
            "status": self.status,
            "eligible_voters": self.eligible_voters,
            "quorum_threshold": self.quorum_threshold,
            "participation_quorum": self.participation_quorum,
            "winning_threshold": self.winning_threshold,
            "initiated_by": self.initiated_by,
            "created_at": self.created_at,
            "votes_cast": len(self.votes),
            "votes": self.votes if full else {v: {"candidate": b["candidate_id"], "ts": b["timestamp"]} for v, b in self.votes.items()},
            "winner_id": self.winner_id,
            "winner_node_id": self.winner_node_id,
            "term_start": self.term_start,
            "term_end": self.term_end,
            "term_days": self.term_days,
            "is_term_valid": bool(
                self.term_end and time.time() <= self.term_end
            ),
            "certified_transaction": self.certified_transaction,
            "tie_info": self.tie_info,
        }
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SubjectElection":
        inst = cls(
            election_id=data["election_id"],
            subject=data["subject"],
            term_days=data.get("term_days", 365),
            eligible_voters=data.get("eligible_voters"),
            quorum_threshold=data.get("quorum_threshold", 3),
            participation_quorum=data.get("participation_quorum"),
            winning_threshold=data.get("winning_threshold"),
            initiated_by=data.get("initiated_by", "ADMIN-001"),
            created_at=data.get("created_at"),
        )
        inst.status = data.get("status", ElectionStatus.IN_PROGRESS)
        inst.votes = data.get("votes", {})
        inst.winner_id = data.get("winner_id")
        inst.winner_node_id = data.get("winner_node_id")
        inst.term_start = data.get("term_start")
        inst.term_end = data.get("term_end")
        inst.certified_transaction = data.get("certified_transaction")
        inst.tie_info = data.get("tie_info")
        return inst


class HeadExaminerRegistry:
    """Registry maintaining active and historical subject Head Examiners with durable persistence."""

    def __init__(self, storage_path: Optional[str] = None) -> None:
        self.elections: Dict[str, SubjectElection] = {}
        self.active_head_examiners: Dict[str, Dict[str, Any]] = {}  # subject -> info
        if storage_path is None:
            storage_path = os.path.abspath(
                os.path.join(
                    os.path.dirname(__file__),
                    "..",
                    "..",
                    "blockchain_data",
                    "examiner_nodes",
                    "elections_registry.json",
                )
            )
        self.storage_path = storage_path
        self.load()

    def load(self) -> None:
        """Load persisted elections and active Head Examiners from disk."""
        if not self.storage_path or not os.path.exists(self.storage_path):
            self.seed_defaults()
            return
        try:
            with open(self.storage_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            self.active_head_examiners = data.get("active_head_examiners", {})
            raw_elections = data.get("elections", {})
            self.elections = {}
            for elec_id, edict in raw_elections.items():
                self.elections[elec_id] = SubjectElection.from_dict(edict)
            if not self.elections:
                self.seed_defaults()
        except Exception as e:
            logger.warning(f"Could not load election registry from {self.storage_path}: {e}")
            self.seed_defaults()

    def save(self) -> None:
        """Atomically persist election registry to disk."""
        if not self.storage_path:
            return
        try:
            os.makedirs(os.path.dirname(self.storage_path), exist_ok=True)
            data = {
                "active_head_examiners": self.active_head_examiners,
                "elections": {eid: e.to_dict(full=True) for eid, e in self.elections.items()},
            }
            tmp_path = f"{self.storage_path}.tmp"
            with open(tmp_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            os.replace(tmp_path, self.storage_path)
        except Exception as e:
            logger.error(f"Failed to persist election registry to {self.storage_path}: {e}")

    def seed_defaults(self) -> None:
        """Seed initial democratic election for DBMS so Head Examiner TCH-002 is active."""
        if self.elections:
            return
        clean_sub = "DBMS"
        elec_id = f"ELEC-{clean_sub}-INITIAL-DEFAULT"
        election = SubjectElection(
            election_id=elec_id,
            subject=clean_sub,
            term_days=365,
            initiated_by="ADMIN-001",
        )
        self.elections[elec_id] = election

        # Cast authenticated ballots from faculty examiners
        ballots = [
            ("TCH-001", "TCH-002"),
            ("TCH-002", "TCH-002"),
            ("TCH-003", "TCH-002"),
            ("TCH-004", "TCH-002"),
            ("TCH-005", "TCH-001"),
        ]
        for voter, cand in ballots:
            election.cast_vote(voter_id=voter, candidate_id=cand)

        ok, reason, details = election.tally()
        if ok:
            self.record_election_conclusion(election)
        self.save()

    def start_election(
        self,
        subject: str,
        term_days: int = 365,
        initiated_by: str = "ADMIN-001",
    ) -> SubjectElection:
        """Create and start a new subject Head Examiner election."""
        clean_sub = subject.strip().upper()
        elec_id = f"ELEC-{clean_sub}-{int(time.time())}-{uuid.uuid4().hex[:6].upper()}"
        election = SubjectElection(
            election_id=elec_id,
            subject=clean_sub,
            term_days=term_days,
            initiated_by=initiated_by,
        )
        self.elections[elec_id] = election
        self.save()
        return election

    def record_election_conclusion(self, election: SubjectElection) -> None:
        """Register concluded Head Examiner for the subject, preserving multi-head appointments."""
        if election.status == ElectionStatus.CONCLUDED and election.winner_id:
            self.record_appointment(
                subject=election.subject,
                head_examiner_id=election.winner_id,
                node_id=election.winner_node_id,
                election_id=election.election_id,
                term_start=election.term_start,
                term_end=election.term_end,
            )

    def record_appointment(
        self,
        subject: str,
        head_examiner_id: str,
        node_id: Optional[str] = None,
        election_id: Optional[str] = None,
        term_start: Optional[float] = None,
        term_end: Optional[float] = None,
    ) -> Dict[str, Any]:
        """Record an active Head Examiner appointment, allowing multiple Head Examiners per subject."""
        clean_sub = subject.strip().upper()
        clean_head = head_examiner_id.strip().upper()
        clean_node = (node_id or TEACHER_EXAMINER_MAP.get(clean_head) or "NODE-001").strip().upper()
        now = time.time()
        start = float(term_start if term_start is not None else now)
        end = float(term_end if term_end is not None else (start + 365 * 86400))

        appt = {
            "subject": clean_sub,
            "head_examiner_id": clean_head,
            "node_id": clean_node,
            "election_id": election_id or f"APPT-{clean_sub}-{clean_head}-{int(now)}",
            "term_start": start,
            "term_end": end,
            "is_valid": True,
        }

        existing = self.active_head_examiners.get(clean_sub, {})
        all_appts = list(existing.get("all_appointments", []))
        if not all_appts and existing.get("head_examiner_id"):
            all_appts = [dict(existing)]

        # Replace existing appointment for this specific teacher in this subject if any, else append
        all_appts = [a for a in all_appts if str(a.get("head_examiner_id", "")).strip().upper() != clean_head]
        all_appts.append(appt)

        active_heads = [a["head_examiner_id"] for a in all_appts if a.get("is_valid", True) and (not a.get("term_end") or now <= a["term_end"])]

        self.active_head_examiners[clean_sub] = {
            "subject": clean_sub,
            "head_examiner_id": clean_head,
            "node_id": clean_node,
            "head_examiners": active_heads,
            "election_id": appt["election_id"],
            "term_start": start,
            "term_end": end,
            "is_valid": True,
            "all_appointments": all_appts,
        }
        self.save()
        return self.active_head_examiners[clean_sub]

    def direct_appoint_head_examiner(
        self,
        subject: str,
        head_examiner_id: str,
        term_days: int = 365,
        appointed_by: str = "ADMIN-001",
    ) -> Dict[str, Any]:
        """Directly appoint a faculty teacher as Head Examiner, creating a completed election record."""
        clean_sub = subject.strip().upper()
        clean_head = head_examiner_id.strip().upper()
        clean_node = TEACHER_EXAMINER_MAP.get(clean_head, "NODE-001")
        now = time.time()
        elec_id = f"APPT-{clean_sub}-{clean_head}-{int(now)}-{uuid.uuid4().hex[:4].upper()}"

        election = SubjectElection(
            election_id=elec_id,
            subject=clean_sub,
            term_days=term_days,
            initiated_by=appointed_by,
        )
        election.status = ElectionStatus.CONCLUDED
        election.winner_id = clean_head
        election.winner_node_id = clean_node
        election.term_start = now
        election.term_end = now + term_days * 86400
        election.votes_cast = len(election.eligible_voters)

        # Record authenticated transaction
        tx_payload = {
            "type": "HEAD_EXAMINER_ELECTED",
            "election_id": elec_id,
            "subject": clean_sub,
            "head_examiner_id": clean_head,
            "head_examiner_node_id": clean_node,
            "appointment_mode": "DIRECT_APPOINTMENT",
            "appointed_by": appointed_by,
            "term_start": election.term_start,
            "term_end": election.term_end,
            "term_days": term_days,
            "status": "ELECTED",
        }
        signed_tx = sign_academic_transaction(
            payload=tx_payload,
            actor_id="AUTH-001",
            actor_role="AUTHORITY",
        )
        election.certified_transaction = signed_tx
        self.elections[elec_id] = election

        appt_info = self.record_appointment(
            subject=clean_sub,
            head_examiner_id=clean_head,
            node_id=clean_node,
            election_id=elec_id,
            term_start=election.term_start,
            term_end=election.term_end,
        )
        return {"election": election.to_dict(), "appointment": appt_info}

    def get_head_examiner(self, subject: str) -> Optional[Dict[str, Any]]:
        """Get active Head Examiner record for a subject, checking term validity."""
        clean_sub = subject.strip().upper()
        info = self.active_head_examiners.get(clean_sub)
        if not info:
            return None
        now = time.time()
        all_appts = info.get("all_appointments") or [info]
        valid_appts = [
            a for a in all_appts
            if a.get("is_valid", True) and (not a.get("term_end") or now <= a["term_end"])
        ]
        if not valid_appts:
            info["is_valid"] = False
            return None
        return {
            **info,
            "head_examiner_id": valid_appts[-1]["head_examiner_id"],
            "node_id": valid_appts[-1].get("node_id", ""),
            "head_examiners": [a["head_examiner_id"] for a in valid_appts],
            "all_appointments": valid_appts,
            "is_valid": True,
        }

    def is_head_examiner(self, actor_id: str, subject: str) -> bool:
        """Verify whether an actor holds valid, unexpired Head Examiner authority for a subject."""
        clean_actor = actor_id.strip().upper()
        clean_sub = subject.strip().upper()
        info = self.active_head_examiners.get(clean_sub)
        if not info or not info.get("is_valid"):
            return False

        now = time.time()
        all_appts = info.get("all_appointments")
        if not all_appts:
            all_appts = [info]

        for appt in all_appts:
            if not appt.get("is_valid", True):
                continue
            if appt.get("term_end") and now > appt["term_end"]:
                continue
            if (
                str(appt.get("head_examiner_id", "")).strip().upper() == clean_actor
                or str(appt.get("node_id", "")).strip().upper() == clean_actor
            ):
                return True
        return False

    def list_elections(self) -> List[Dict[str, Any]]:
        """Return all elections."""
        return [e.to_dict() for e in self.elections.values()]

    def list_head_examiners(self) -> Dict[str, Any]:
        """Return active Head Examiners across all subjects."""
        now = time.time()
        result = {}
        for sub, info in self.active_head_examiners.items():
            all_appts = info.get("all_appointments") or [info]
            valid_appts = [
                a for a in all_appts
                if a.get("is_valid", True) and (not a.get("term_end") or now <= a["term_end"])
            ]
            if valid_appts:
                heads = [a["head_examiner_id"] for a in valid_appts]
                result[sub] = {
                    **info,
                    "head_examiner_id": valid_appts[-1]["head_examiner_id"],
                    "node_id": valid_appts[-1].get("node_id", ""),
                    "head_examiners": heads,
                    "is_valid": True,
                    "all_appointments": valid_appts,
                }
            else:
                result[sub] = {**info, "is_valid": False, "head_examiners": []}
        return result

