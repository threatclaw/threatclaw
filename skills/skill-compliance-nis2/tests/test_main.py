"""Tests for skill-compliance-nis2."""

import pytest
from src.main import NIS2_ARTICLES, SkillInput, run


def test_nis2_articles_complete():
    assert len(NIS2_ARTICLES) == 10


@pytest.mark.asyncio
async def test_run_default():
    output = await run(SkillInput())
    assert output.success is True
    assert output.report is not None
    assert len(output.report.article_scores) == 10
