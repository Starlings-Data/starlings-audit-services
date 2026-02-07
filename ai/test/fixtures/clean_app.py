# Clean Python file — should NOT trigger any findings
# This file demonstrates secure AI/LLM patterns

import os
from anthropic import Anthropic

# Correct: API key from environment
client = Anthropic(api_key=os.environ.get("ANTHROPIC_API_KEY"))

def chat(user_message: str) -> str:
    """Secure chat function with proper input handling."""
    # Correct: Input validation
    if not user_message or len(user_message) > 4000:
        raise ValueError("Invalid input length")

    # Correct: User input in separate message role, not interpolated into system prompt
    response = client.messages.create(
        model="claude-sonnet-4-5-20250929",
        max_tokens=1024,
        system="You are a helpful assistant.",
        messages=[
            {"role": "user", "content": user_message}
        ]
    )
    return response.content[0].text
