"""
Compatibility wrapper for syslog listener.
This keeps the enterprise folder layout without breaking current imports.
"""

from syslog_listener import SyslogListener, SyslogUDPHandler, SyslogTCPHandler, enqueue_alert  # noqa: F401

__all__ = ["SyslogListener", "SyslogUDPHandler", "SyslogTCPHandler", "enqueue_alert"]
