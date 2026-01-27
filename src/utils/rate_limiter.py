"""
Rate Limiter

Provides rate limiting functionality for EPP commands.
Supports per-client and per-account rate limits with configurable windows.
"""

import asyncio
import logging
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger("epp.rate_limiter")


@dataclass
class RateLimitConfig:
    """Rate limit configuration."""
    # Commands per second (0 = unlimited)
    commands_per_second: int = 0
    # Commands per minute (0 = unlimited)
    commands_per_minute: int = 0
    # Commands per hour (0 = unlimited)
    commands_per_hour: int = 0
    # Burst allowance (extra commands allowed in a burst)
    burst_allowance: int = 10
    # Cooldown period after limit hit (seconds)
    cooldown_seconds: int = 60
    # Whether to block or just warn when limit hit
    enforce: bool = True


@dataclass
class RateLimitEntry:
    """Tracks rate limit state for a client."""
    # Timestamps of recent commands
    timestamps: List[datetime] = field(default_factory=list)
    # Cooldown until timestamp
    cooldown_until: Optional[datetime] = None
    # Total commands blocked
    blocked_count: int = 0
    # Last warning time
    last_warning: Optional[datetime] = None


@dataclass
class SessionStats:
    """Statistics for a session."""
    # Command counts by type
    command_counts: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    # Total commands
    total_commands: int = 0
    # Successful commands
    successful_commands: int = 0
    # Failed commands
    failed_commands: int = 0
    # Bytes sent
    bytes_sent: int = 0
    # Bytes received
    bytes_received: int = 0
    # Session start time
    start_time: datetime = field(default_factory=datetime.utcnow)
    # Last activity time
    last_activity: datetime = field(default_factory=datetime.utcnow)
    # Peak commands per second
    peak_cps: float = 0.0
    # Commands in current second
    current_second_commands: int = 0
    current_second_start: datetime = field(default_factory=datetime.utcnow)

    def record_command(self, command_type: str, success: bool = True) -> None:
        """Record a command execution."""
        now = datetime.utcnow()
        self.total_commands += 1
        self.command_counts[command_type] += 1

        if success:
            self.successful_commands += 1
        else:
            self.failed_commands += 1

        self.last_activity = now

        # Track peak CPS
        if (now - self.current_second_start).total_seconds() < 1:
            self.current_second_commands += 1
        else:
            if self.current_second_commands > self.peak_cps:
                self.peak_cps = self.current_second_commands
            self.current_second_commands = 1
            self.current_second_start = now

    def record_bytes(self, sent: int = 0, received: int = 0) -> None:
        """Record bytes transferred."""
        self.bytes_sent += sent
        self.bytes_received += received

    def get_session_duration(self) -> timedelta:
        """Get session duration."""
        return datetime.utcnow() - self.start_time

    def get_commands_per_minute(self) -> float:
        """Calculate average commands per minute."""
        duration = self.get_session_duration()
        minutes = duration.total_seconds() / 60
        if minutes < 0.0167:  # Less than 1 second
            return 0.0
        return self.total_commands / minutes

    def to_dict(self) -> Dict:
        """Convert to dictionary for serialization."""
        duration = self.get_session_duration()
        return {
            "total_commands": self.total_commands,
            "successful_commands": self.successful_commands,
            "failed_commands": self.failed_commands,
            "command_counts": dict(self.command_counts),
            "bytes_sent": self.bytes_sent,
            "bytes_received": self.bytes_received,
            "session_duration_seconds": duration.total_seconds(),
            "commands_per_minute": self.get_commands_per_minute(),
            "peak_cps": self.peak_cps,
            "start_time": self.start_time.isoformat(),
            "last_activity": self.last_activity.isoformat(),
        }


class RateLimiter:
    """
    Rate limiter for EPP commands.

    Tracks command rates per client IP and per account.
    Supports multiple time windows (second, minute, hour).
    """

    def __init__(self, config: Optional[RateLimitConfig] = None):
        """
        Initialize rate limiter.

        Args:
            config: Rate limit configuration (uses defaults if None)
        """
        self.config = config or RateLimitConfig()
        # Rate limit entries by client IP
        self._by_ip: Dict[str, RateLimitEntry] = defaultdict(RateLimitEntry)
        # Rate limit entries by account ID
        self._by_account: Dict[int, RateLimitEntry] = defaultdict(RateLimitEntry)
        # Lock for thread safety
        self._lock = asyncio.Lock()
        # Cleanup task
        self._cleanup_task: Optional[asyncio.Task] = None

    def start(self) -> None:
        """Start the rate limiter (cleanup task)."""
        if self._cleanup_task is None:
            self._cleanup_task = asyncio.create_task(self._cleanup_loop())
            logger.info("Rate limiter started")

    def stop(self) -> None:
        """Stop the rate limiter."""
        if self._cleanup_task:
            self._cleanup_task.cancel()
            self._cleanup_task = None
            logger.info("Rate limiter stopped")

    async def _cleanup_loop(self) -> None:
        """Periodically clean up old rate limit entries."""
        try:
            while True:
                await asyncio.sleep(300)  # Clean up every 5 minutes
                await self._cleanup_old_entries()
        except asyncio.CancelledError:
            pass

    async def _cleanup_old_entries(self) -> None:
        """Remove old timestamps and inactive entries."""
        async with self._lock:
            now = datetime.utcnow()
            cutoff = now - timedelta(hours=2)  # Keep 2 hours of data

            # Clean IP entries
            to_remove_ip = []
            for ip, entry in self._by_ip.items():
                entry.timestamps = [ts for ts in entry.timestamps if ts > cutoff]
                if not entry.timestamps and (entry.cooldown_until is None or entry.cooldown_until < now):
                    to_remove_ip.append(ip)

            for ip in to_remove_ip:
                del self._by_ip[ip]

            # Clean account entries
            to_remove_account = []
            for account_id, entry in self._by_account.items():
                entry.timestamps = [ts for ts in entry.timestamps if ts > cutoff]
                if not entry.timestamps and (entry.cooldown_until is None or entry.cooldown_until < now):
                    to_remove_account.append(account_id)

            for account_id in to_remove_account:
                del self._by_account[account_id]

            if to_remove_ip or to_remove_account:
                logger.debug(f"Cleaned up {len(to_remove_ip)} IP entries and {len(to_remove_account)} account entries")

    async def check_rate_limit(
        self,
        client_ip: str,
        account_id: Optional[int] = None
    ) -> Tuple[bool, Optional[str]]:
        """
        Check if a command is allowed within rate limits.

        Args:
            client_ip: Client IP address
            account_id: Optional account ID

        Returns:
            Tuple of (allowed, reason if not allowed)
        """
        if not self.config.enforce:
            return True, None

        # Skip if no limits configured
        if (self.config.commands_per_second == 0 and
            self.config.commands_per_minute == 0 and
            self.config.commands_per_hour == 0):
            return True, None

        async with self._lock:
            now = datetime.utcnow()

            # Check IP-based limit
            ip_entry = self._by_ip[client_ip]
            allowed, reason = self._check_entry(ip_entry, now, f"IP {client_ip}")
            if not allowed:
                return False, reason

            # Check account-based limit
            if account_id is not None:
                account_entry = self._by_account[account_id]
                allowed, reason = self._check_entry(account_entry, now, f"account {account_id}")
                if not allowed:
                    return False, reason

            return True, None

    def _check_entry(
        self,
        entry: RateLimitEntry,
        now: datetime,
        identifier: str
    ) -> Tuple[bool, Optional[str]]:
        """
        Check rate limit for a single entry.

        Args:
            entry: Rate limit entry
            now: Current time
            identifier: Identifier for logging

        Returns:
            Tuple of (allowed, reason if not allowed)
        """
        # Check cooldown
        if entry.cooldown_until and entry.cooldown_until > now:
            remaining = (entry.cooldown_until - now).total_seconds()
            return False, f"Rate limit cooldown active for {identifier}, {remaining:.0f}s remaining"

        # Count commands in each window
        one_second_ago = now - timedelta(seconds=1)
        one_minute_ago = now - timedelta(minutes=1)
        one_hour_ago = now - timedelta(hours=1)

        commands_per_second = sum(1 for ts in entry.timestamps if ts > one_second_ago)
        commands_per_minute = sum(1 for ts in entry.timestamps if ts > one_minute_ago)
        commands_per_hour = sum(1 for ts in entry.timestamps if ts > one_hour_ago)

        # Check per-second limit
        if self.config.commands_per_second > 0:
            if commands_per_second >= self.config.commands_per_second + self.config.burst_allowance:
                self._apply_cooldown(entry, now, identifier)
                return False, f"Rate limit exceeded for {identifier}: {commands_per_second}/s"

        # Check per-minute limit
        if self.config.commands_per_minute > 0:
            if commands_per_minute >= self.config.commands_per_minute:
                self._apply_cooldown(entry, now, identifier)
                return False, f"Rate limit exceeded for {identifier}: {commands_per_minute}/min"

        # Check per-hour limit
        if self.config.commands_per_hour > 0:
            if commands_per_hour >= self.config.commands_per_hour:
                self._apply_cooldown(entry, now, identifier)
                return False, f"Rate limit exceeded for {identifier}: {commands_per_hour}/hour"

        return True, None

    def _apply_cooldown(
        self,
        entry: RateLimitEntry,
        now: datetime,
        identifier: str
    ) -> None:
        """Apply cooldown to an entry."""
        entry.cooldown_until = now + timedelta(seconds=self.config.cooldown_seconds)
        entry.blocked_count += 1

        # Rate-limit warnings
        if entry.last_warning is None or (now - entry.last_warning).total_seconds() > 60:
            logger.warning(f"Rate limit triggered for {identifier}, cooldown applied")
            entry.last_warning = now

    async def record_command(
        self,
        client_ip: str,
        account_id: Optional[int] = None
    ) -> None:
        """
        Record a command for rate limiting.

        Args:
            client_ip: Client IP address
            account_id: Optional account ID
        """
        async with self._lock:
            now = datetime.utcnow()

            # Record for IP
            self._by_ip[client_ip].timestamps.append(now)

            # Record for account
            if account_id is not None:
                self._by_account[account_id].timestamps.append(now)

    def get_stats(self, client_ip: str = None, account_id: int = None) -> Dict:
        """
        Get rate limit statistics.

        Args:
            client_ip: Optional IP to get stats for
            account_id: Optional account to get stats for

        Returns:
            Statistics dictionary
        """
        stats = {
            "config": {
                "commands_per_second": self.config.commands_per_second,
                "commands_per_minute": self.config.commands_per_minute,
                "commands_per_hour": self.config.commands_per_hour,
                "enforce": self.config.enforce,
            },
            "total_ips_tracked": len(self._by_ip),
            "total_accounts_tracked": len(self._by_account),
        }

        if client_ip and client_ip in self._by_ip:
            entry = self._by_ip[client_ip]
            now = datetime.utcnow()
            one_minute_ago = now - timedelta(minutes=1)
            stats["ip_stats"] = {
                "ip": client_ip,
                "commands_last_minute": sum(1 for ts in entry.timestamps if ts > one_minute_ago),
                "blocked_count": entry.blocked_count,
                "in_cooldown": entry.cooldown_until is not None and entry.cooldown_until > now,
            }

        if account_id and account_id in self._by_account:
            entry = self._by_account[account_id]
            now = datetime.utcnow()
            one_minute_ago = now - timedelta(minutes=1)
            stats["account_stats"] = {
                "account_id": account_id,
                "commands_last_minute": sum(1 for ts in entry.timestamps if ts > one_minute_ago),
                "blocked_count": entry.blocked_count,
                "in_cooldown": entry.cooldown_until is not None and entry.cooldown_until > now,
            }

        return stats


# Global rate limiter instance
_rate_limiter: Optional[RateLimiter] = None


def initialize_rate_limiter(config: Optional[RateLimitConfig] = None) -> RateLimiter:
    """
    Initialize the global rate limiter.

    Args:
        config: Rate limit configuration

    Returns:
        RateLimiter instance
    """
    global _rate_limiter
    _rate_limiter = RateLimiter(config)
    return _rate_limiter


def get_rate_limiter() -> Optional[RateLimiter]:
    """Get the global rate limiter instance."""
    return _rate_limiter
