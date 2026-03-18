"""Tests for skill-email-audit."""

import pytest
from src.main import SkillInput, run


@pytest.mark.asyncio
async def test_run_empty_input():
    output = await run(SkillInput())
    assert output.success is True
    assert len(output.audits) == 0
