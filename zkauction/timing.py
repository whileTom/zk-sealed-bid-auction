"""Timing rules shared by the bidding and reveal phases.

A bid (or reveal) counts if its complete request ARRIVED before the deadline, even though
verifying its proof takes a moment. To keep published results stable, the server:
  - stops inserting anything whose verification finishes later than deadline + SETTLE_GRACE, and
  - only reports `final` / `winner` once that grace period has passed,
so a result announced as final can never change afterwards.

VERIFY_SLOTS caps how many CPU-heavy proof verifications run at once. Waiting threads release
the GIL, which keeps the event loop free to stamp arrival times promptly under load.
"""
import threading
from datetime import timedelta

SETTLE_GRACE = timedelta(seconds=10)
VERIFY_SLOTS = threading.BoundedSemaphore(2)
