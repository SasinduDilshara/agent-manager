"""A two-agent CrewAI crew.

A researcher (with one tool) and an editor run two sequential tasks. The
researcher answers the question using the lookup tool, and the editor shortens
the answer. Each /chat call runs both agents and the model behind them, so a
single request produces a small multi-agent trace. Pinned to crewai 1.1.0 for
dependency compatibility.

Through the AI gateway: when the platform injects an LLM proxy (LLM_PROXY_URL,
LLM_PROXY_API_KEY) the agents call the model through it instead of OpenAI
directly, and when it injects an MCP proxy (WEATHER_MCP_URL,
WEATHER_MCP_API_KEY) the researcher can also call that server's weather tools.
Either way the calls pass the gateway, which reports them to the audit trail.
Without these variables the crew calls OpenAI directly, as before.
"""
from __future__ import annotations

import os

from crewai import LLM, Agent, Crew, Process, Task
from crewai.mcp import MCPServerHTTP
from crewai.tools import tool

MODEL = "gpt-4o-mini"


def _model() -> LLM | str:
    """The model, through the gateway's LLM proxy when one is configured."""
    url = os.getenv("LLM_PROXY_URL")
    key = os.getenv("LLM_PROXY_API_KEY")
    if not url or not key:
        return MODEL
    # The proxy authenticates callers by an API-Key header, not the OpenAI
    # Authorization header, and holds the provider credential itself.
    header = os.getenv("LLM_PROXY_API_KEY_HEADER", "API-Key")
    return LLM(model=MODEL, base_url=url, api_key=key, default_headers={header: key})


def _mcp_servers() -> list[MCPServerHTTP]:
    """The weather MCP server, through the gateway's MCP proxy when configured."""
    url = os.getenv("WEATHER_MCP_URL")
    key = os.getenv("WEATHER_MCP_API_KEY")
    if not url or not key:
        return []
    header = os.getenv("WEATHER_MCP_API_KEY_HEADER", "X-API-Key")
    return [MCPServerHTTP(url=url, headers={header: key})]


@tool("country_capital_lookup")
def country_capital_lookup(country: str) -> str:
    """Return the capital city of a country."""
    return f"The capital of {country} is Paris."


def create_crew() -> Crew:
    mcps = _mcp_servers()
    researcher = Agent(
        role="Geography researcher",
        goal=(
            "Answer the user's question, using the lookup tool for capitals"
            + (" and the weather tools for weather and forecasts." if mcps else ".")
        ),
        backstory="You call your tools to answer geography and weather questions.",
        llm=_model(),
        tools=[country_capital_lookup],
        mcps=mcps,
        allow_delegation=False,
        verbose=False,
    )
    editor = Agent(
        role="Editor",
        goal="Shorten the researcher's answer to a single short sentence.",
        backstory="You compress answers to the minimum useful form.",
        llm=_model(),
        allow_delegation=False,
        verbose=False,
    )

    research_task = Task(
        description="Today's date is {today}. Answer the user's question: {question}",
        expected_output="A sentence answering the question.",
        agent=researcher,
    )
    edit_task = Task(
        description="Shorten the researcher's previous answer to one short sentence.",
        expected_output="One short sentence.",
        agent=editor,
        context=[research_task],
    )

    return Crew(
        agents=[researcher, editor],
        tasks=[research_task, edit_task],
        process=Process.sequential,
        verbose=False,
    )
