"""Tests for skill-appsec."""

import pytest
from src.main import SkillInput, run


@pytest.mark.asyncio
async def test_run_empty():
    output = await run(SkillInput())
    assert output.success is True
