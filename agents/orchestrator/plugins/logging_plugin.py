# ============================================================================
# agents/orchestrator/plugins/logging_plugin.py
# Enhanced logging plugin for observability
# ============================================================================

import logging
from google.adk.agents.base_agent import BaseAgent
from google.adk.agents.callback_context import CallbackContext
from google.adk.models.llm_request import LlmRequest
from google.adk.plugins.base_plugin import BasePlugin
from datetime import datetime


class EnhancedLoggingPlugin(BasePlugin):
    """Enhanced logging plugin with metrics tracking"""

    def __init__(self) -> None:
        super().__init__(name="enhanced_logging")
        self.agent_count = 0
        self.tool_count = 0
        self.llm_request_count = 0
        self.start_time = None
        
        # Setup logger
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger('AutoForensics')

    async def before_agent_callback(
        self, *, agent: BaseAgent, callback_context: CallbackContext
    ) -> None:
        """Log before agent execution"""
        if self.start_time is None:
            self.start_time = datetime.now()
        
        self.agent_count += 1
        self.logger.info(
            f"🤖 Agent Starting: {agent.name} (Invocation #{self.agent_count})"
        )

    async def after_agent_callback(
        self, *, agent: BaseAgent, callback_context: CallbackContext
    ) -> None:
        """Log after agent execution"""
        elapsed = (datetime.now() - self.start_time).total_seconds()
        self.logger.info(
            f"✅ Agent Completed: {agent.name} (Elapsed: {elapsed:.2f}s)"
        )

    async def before_model_callback(
        self, *, callback_context: CallbackContext, llm_request: LlmRequest
    ) -> None:
        """Log before LLM request"""
        self.llm_request_count += 1
        self.logger.info(
            f"🧠 LLM Request #{self.llm_request_count} - Model: {llm_request.model}"
        )

    async def after_model_callback(
        self, *, callback_context: CallbackContext, llm_response
    ) -> None:
        """Log after LLM response"""
        try:
            token_usage = getattr(llm_response, 'usage_metadata', None)
            if token_usage:
                self.logger.info(
                    f"📊 Tokens - Input: {token_usage.prompt_token_count}, "
                    f"Output: {token_usage.candidates_token_count}"
                )
        except:
            pass

    async def before_tool_callback(
        self, *, tool_name: str, callback_context: CallbackContext
    ) -> None:
        """Log before tool execution"""
        self.tool_count += 1
        self.logger.info(f"🔧 Tool Executing: {tool_name} (Call #{self.tool_count})")

    async def after_tool_callback(
        self, *, tool_name: str, callback_context: CallbackContext
    ) -> None:
        """Log after tool execution"""
        self.logger.info(f"✅ Tool Completed: {tool_name}")
