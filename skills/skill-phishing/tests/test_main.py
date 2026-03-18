"""Tests for skill-phishing."""

import pytest
from src.main import SkillInput, run


@pytest.mark.asyncio
async def test_run_creates_campaign():
    output = await run(SkillInput(target_group="test-group"))
    assert output.success is True
