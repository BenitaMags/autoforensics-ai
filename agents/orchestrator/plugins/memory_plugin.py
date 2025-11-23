# ============================================================================
# agents/orchestrator/plugins/memory_plugin.py
# Auto-save to Memory Bank plugin
# ============================================================================

from google.adk.agents.callback_context import CallbackContext
from google.adk.plugins.base_plugin import BasePlugin


class MemoryBankPlugin(BasePlugin):
    """Automatically save sessions to Memory Bank"""

    def __init__(self) -> None:
        super().__init__(name="memory_bank_auto_save")

    async def after_agent_callback(self, *, callback_context: CallbackContext, agent) -> None:
        """Save session to memory after each agent turn"""
        try:
            invocation_context = callback_context._invocation_context
            
            # Only save if memory service is available
            if hasattr(invocation_context, 'memory_service') and invocation_context.memory_service:
                session = invocation_context.session
                await invocation_context.memory_service.add_session_to_memory(session)
        except Exception as e:
            # Don't fail the workflow if memory save fails
            print(f"⚠️  Memory save failed: {e}")
