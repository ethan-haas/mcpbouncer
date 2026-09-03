"""mcpbouncer -- a declared-policy gate that sits in front of MCP servers.

Every ``tools/call`` is checked against a versioned policy before it is
forwarded to the upstream server. Allowed calls pass through unchanged.
Denied calls return a structured error naming the rule that denied them.
A call the policy cannot classify is DENIED, never forwarded.
"""

from mcpbouncer.policy import Policy, PolicyError, load_policy
from mcpbouncer.engine import Decision, Engine

__all__ = [
    "Policy",
    "PolicyError",
    "load_policy",
    "Decision",
    "Engine",
]

__version__ = "0.1.0"
