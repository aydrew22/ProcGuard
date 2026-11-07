"""Plain data classes shared across ProcGuard."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Tuple


class Level(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class ProcessInfo:
    """A snapshot of one running process, gathered by the collector."""

    pid: int
    ppid: Optional[int]
    name: str
    exe: Optional[str]
    cmdline: List[str]
    username: Optional[str]
    create_time: Optional[float]
    status: Optional[str]
    num_threads: int
    cpu_percent: float  # share of TOTAL machine CPU, 0-100 (like Task Manager)
    mem_percent: float
    mem_rss: int  # bytes
    parent_name: Optional[str] = None
    remote: List[Tuple[str, int]] = field(default_factory=list)  # established connections
    listening: List[Tuple[str, int]] = field(default_factory=list)  # listening sockets

    @property
    def key(self) -> Tuple[int, Optional[float]]:
        """Identity that survives PID reuse."""
        return (self.pid, self.create_time)

    @property
    def cmd(self) -> str:
        return " ".join(self.cmdline)


@dataclass
class Reason:
    """One explainable reason that contributed to a risk score."""

    points: int
    text: str
    category: str = "behavior"  # location | identity | behavior | network | resource | info


@dataclass
class RiskResult:
    score: int
    level: Level
    reasons: List[Reason]
    description: str


@dataclass
class Assessed:
    info: ProcessInfo
    risk: RiskResult
