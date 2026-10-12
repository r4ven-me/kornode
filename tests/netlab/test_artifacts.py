from __future__ import annotations

import pytest

pytest_plugins = ["pytester"]


@pytest.mark.netlab
def test_failed_netlab_test_writes_namespace_artifacts(pytester: pytest.Pytester) -> None:
    pytester.makeconftest("from tests.netlab.conftest import *  # noqa: F403\n")
    pytester.makepyfile(
        test_failure="""
        import pytest

        @pytest.mark.netlab
        def test_failure_creates_artifact(lab):
            lab.add_namespace("probe")
            assert False
        """
    )

    result = pytester.runpytest_inprocess("-v")

    result.assert_outcomes(failed=1)
    artifact_files = sorted(pytester.path.glob("artifacts/netlab/*/probe.txt"))
    assert len(artifact_files) == 1
    assert "### ip rule" in artifact_files[0].read_text(encoding="utf-8")
