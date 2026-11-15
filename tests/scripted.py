"""A scripted stand-in for a model, shared by the agent tests and the ADK eval check.

It plays an obedient agent: the planner hands any request to remediation, and
remediation looks at core-use1-02 and then proposes restarting authd on it,
whether or not anyone is allowed to. No real model is called.
"""

import asyncio
import json

from google.adk.models.base_llm import BaseLlm
from google.adk.models.llm_response import LlmResponse
from google.adk.runners import InMemoryRunner
from google.genai import types

SEEN = []          # every request any agent's model received


def call(name, **args):
    return types.Part(function_call=types.FunctionCall(name=name, args=args))


def payload(response: dict) -> dict:
    """The gateway's reply, however the tool delivered it (directly or over MCP)."""
    if "decision" in response:
        return response
    if isinstance(response.get("structuredContent"), dict) and \
            "decision" in response["structuredContent"]:
        return response["structuredContent"]
    for item in response.get("content", []):
        if item.get("type") == "text":
            return json.loads(item["text"])
    return response


class Scripted(BaseLlm):
    model: str = "scripted"

    async def generate_content_async(self, llm_request, stream=False):
        SEEN.append(llm_request)
        tools = set(llm_request.tools_dict)
        last = llm_request.contents[-1]
        responses = [p.function_response for p in last.parts if p.function_response]
        if "restart_service" in tools:                              # remediation
            if not responses:
                part = call("get_server", host="core-use1-02")
            elif responses[0].name == "get_server":
                part = call("restart_service", host="core-use1-02", service="authd")
            else:
                reply = payload(responses[0].response)
                how = (reply.get("approval") or {}).get("how", "")
                part = types.Part(text=f"{reply['decision']}: {how}")
        elif "remediation" in tools:                                # planner
            if not responses:
                part = call("remediation", request="restart authd on core-use1-02")
            else:
                part = types.Part(text="Reported: " + json.dumps(responses[0].response))
        else:
            part = types.Part(text="nothing to do")
        yield LlmResponse(content=types.Content(role="model", parts=[part]))


def run(agent, text):
    """Run one user turn and return [(author, text), ...]."""
    async def go():
        runner = InMemoryRunner(agent=agent, app_name="fde-test")
        try:
            session = await runner.session_service.create_session(app_name="fde-test",
                                                                  user_id="u")
            texts = []
            async for event in runner.run_async(
                    user_id="u", session_id=session.id,
                    new_message=types.Content(role="user", parts=[types.Part(text=text)])):
                for part in (event.content.parts if event.content else []):
                    if part.text:
                        texts.append((event.author, part.text))
            return texts
        finally:
            await runner.close()          # shuts down any MCP server the agents started
    return asyncio.run(go())
