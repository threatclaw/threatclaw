"""Tests for skill-secrets."""

import pytest
from src.main import SkillInput, run


@pytest.mark.asyncio
async def test_run_empty_input():
    output = await run(SkillInput())
    assert output.success is True
    assert output.result.repositories_scanned == 0
    assert len(output.result.findings) == 0
