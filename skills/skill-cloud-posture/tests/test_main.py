"""Tests for skill-cloud-posture."""

import pytest
from src.main import SkillInput, run


@pytest.mark.asyncio
async def test_run_default():
    output = await run(SkillInput())
    assert output.success is True
