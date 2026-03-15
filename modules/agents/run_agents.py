# modules/agents/run_agents.py
"""
Einstiegspunkt für den Multi-Agent Workflow.
Kann sowohl synchron (CLI) als auch mit Streaming (GUI) genutzt werden.
"""
from .orchestrator import run_full_analysis, stream_analysis

__all__ = ["run_full_analysis", "stream_analysis"]
