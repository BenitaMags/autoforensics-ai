# ============================================================================
# agents/orchestrator/plugins/metrics_plugin.py
# Metrics tracking plugin
# ============================================================================

import time
from typing import Dict, Any
from google.adk.agents.base_agent import BaseAgent
from google.adk.agents.callback_context import CallbackContext
from google.adk.plugins.base_plugin import BasePlugin


class MetricsPlugin(BasePlugin):
    """Track metrics for performance monitoring"""

    def __init__(self) -> None:
        super().__init__(name="metrics_tracking")
        self.metrics = {
            'total_agents': 0,
            'total_tools': 0,
            'total_llm_calls': 0,
            'agent_timings': {},
            'tool_timings': {},
            'start_time': None,
            'end_time': None
        }
        self._current_agent_start = None
        self._current_tool_start = None

    async def before_agent_callback(
        self, *, agent: BaseAgent, callback_context: CallbackContext
    ) -> None:
        """Start timing agent execution"""
        if self.metrics['start_time'] is None:
            self.metrics['start_time'] = time.time()
        
        self.metrics['total_agents'] += 1
        self._current_agent_start = time.time()

    async def after_agent_callback(
        self, *, agent: BaseAgent, callback_context: CallbackContext
    ) -> None:
        """Record agent execution time"""
        if self._current_agent_start:
            elapsed = time.time() - self._current_agent_start
            if agent.name not in self.metrics['agent_timings']:
                self.metrics['agent_timings'][agent.name] = []
            self.metrics['agent_timings'][agent.name].append(elapsed)

    async def before_tool_callback(
        self, *, tool_name: str, callback_context: CallbackContext
    ) -> None:
        """Start timing tool execution"""
        self.metrics['total_tools'] += 1
        self._current_tool_start = time.time()

    async def after_tool_callback(
        self, *, tool_name: str, callback_context: CallbackContext
    ) -> None:
        """Record tool execution time"""
        if self._current_tool_start:
            elapsed = time.time() - self._current_tool_start
            if tool_name not in self.metrics['tool_timings']:
                self.metrics['tool_timings'][tool_name] = []
            self.metrics['tool_timings'][tool_name].append(elapsed)

    async def before_model_callback(
        self, *, callback_context: CallbackContext, llm_request
    ) -> None:
        """Count LLM requests"""
        self.metrics['total_llm_calls'] += 1

    def get_metrics(self) -> Dict[str, Any]:
        """Get all collected metrics"""
        self.metrics['end_time'] = time.time()
        total_time = self.metrics['end_time'] - self.metrics['start_time']
        
        # Calculate averages
        avg_timings = {}
        for agent, timings in self.metrics['agent_timings'].items():
            avg_timings[agent] = sum(timings) / len(timings) if timings else 0
        
        return {
            'total_agents': self.metrics['total_agents'],
            'total_tools': self.metrics['total_tools'],
            'total_llm_calls': self.metrics['total_llm_calls'],
            'total_time': round(total_time, 2),
            'average_agent_timings': avg_timings,
            'agent_call_counts': {k: len(v) for k, v in self.metrics['agent_timings'].items()}
        }
