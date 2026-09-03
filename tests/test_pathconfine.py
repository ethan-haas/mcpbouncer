"""Gate 4: path confinement is adversarial. Each variant is its own test;
a fix covering only some of them must fail this gate."""

import os

import pytest

from mcpbouncer.pathconfine import is_under_root

ROOT = "/srv/app"


def test_dotdot_traversal_denied():
    ok, resolved = is_under_root("/srv/app/../../etc/passwd", ROOT)
    assert ok is False
    assert resolved == "/etc/passwd"


def test_dotdot_within_root_allowed():
    ok, resolved = is_under_root("/srv/app/sub/../file.txt", ROOT)
    assert ok is True
    assert resolved == "/srv/app/file.txt"


def test_absolute_path_outside_root_denied():
    ok, _ = is_under_root("/etc/shadow", ROOT)
    assert ok is False


def test_absolute_path_inside_root_allowed():
    ok, _ = is_under_root("/srv/app/data/file.txt", ROOT)
    assert ok is True


def test_separator_less_prefix_denied():
    """'/srv/appdata' must NOT be considered under root '/srv/app' -- a raw
    string startswith() check would wrongly admit this."""
    ok, _ = is_under_root("/srv/appdata/secrets.env", ROOT)
    assert ok is False


def test_separator_less_prefix_exact_root_name_allowed():
    ok, _ = is_under_root("/srv/app/appdata/file.txt", ROOT)
    assert ok is True


def test_unicode_fullwidth_separator_denied():
    """A fullwidth solidus (U+FF0F) NFKC-normalizes to '/', so a naive
    string-only check that never normalizes would miss this traversal."""
    ok, resolved = is_under_root("/srv／app／..／..／etc／passwd", ROOT)
    assert ok is False
    assert resolved == "/etc/passwd"


def test_backslash_treated_as_separator_denied():
    ok, _ = is_under_root("/srv/app\\..\\..\\etc\\passwd", ROOT)
    assert ok is False


def test_relative_path_anchored_and_confined():
    ok, _ = is_under_root("../../etc/passwd", ROOT)
    assert ok is False


@pytest.mark.skipif(os.name == "nt", reason="creating symlinks on Windows needs elevated privileges/dev mode")
def test_symlink_escape_denied(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    secret = outside / "secret.txt"
    secret.write_text("top secret", encoding="utf-8")

    root_dir = tmp_path / "app"
    root_dir.mkdir()
    link = root_dir / "escape_link"
    try:
        link.symlink_to(secret)
    except OSError:
        pytest.skip("symlink creation not permitted in this environment")

    root_posix = str(root_dir).replace("\\", "/")
    link_posix = str(link).replace("\\", "/")
    ok, resolved = is_under_root(link_posix, root_posix)
    assert ok is False
    assert "outside" in resolved


@pytest.mark.skipif(os.name == "nt", reason="creating symlinks on Windows needs elevated privileges/dev mode")
def test_symlink_within_root_allowed(tmp_path):
    root_dir = tmp_path / "app"
    root_dir.mkdir()
    real_file = root_dir / "real.txt"
    real_file.write_text("fine", encoding="utf-8")
    link = root_dir / "alias.txt"
    try:
        link.symlink_to(real_file)
    except OSError:
        pytest.skip("symlink creation not permitted in this environment")

    root_posix = str(root_dir).replace("\\", "/")
    link_posix = str(link).replace("\\", "/")
    ok, _ = is_under_root(link_posix, root_posix)
    assert ok is True
