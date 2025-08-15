"""
Extra tests for honoring encrypted_regex in .sops.yaml
"""
from pathlib import Path

import pytest

from pre_commit_hook_ensure_sops.__main__ import check_file

SOPS_CONFIG = """
creation_rules:
  - encrypted_regex: '^(data|stringData)$'
"""

ENCRYPTED_OK = """
foo: plain_text
data: ENC[AES256_GCM,data:dummy,iv:iv,tag:tag,type:str]
sops:
"""

ENCRYPTED_MISSING = """
foo: plain_text
data: plain_text
sops:
"""


@pytest.mark.parametrize(
    "content,expect_valid",
    [
        pytest.param(ENCRYPTED_OK, True, id="encrypted_ok"),
        pytest.param(ENCRYPTED_MISSING, False, id="encrypted_missing"),
    ],
)
def test_encrypted_regex(tmp_path: Path, content: str, expect_valid: bool, monkeypatch):
    """
    Ensure that only keys matching encrypted_regex are validated.
    """
    # Write .sops.yaml
    (tmp_path / ".sops.yaml").write_text(SOPS_CONFIG)

    # Create secret file
    secret_file = tmp_path / "secret.yaml"
    secret_file.write_text(content)

    # Run check_file from the tmp path
    monkeypatch.chdir(tmp_path)
    is_valid, _ = check_file(secret_file.as_posix())
    assert is_valid == expect_valid
