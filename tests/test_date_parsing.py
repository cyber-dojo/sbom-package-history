import pytest

from sbom_package_history.date_parsing import parse_date_to_epoch


def test_c3a7e001():
    """A bare date is interpreted as midnight UTC."""
    assert parse_date_to_epoch("2026-06-01") == 1780272000


def test_c3a7e002():
    """A date and time is interpreted in UTC."""
    assert parse_date_to_epoch("2026-06-01 09:12") == 1780305120


def test_c3a7e003():
    """The ISO T separator between date and time is accepted."""
    assert parse_date_to_epoch("2026-06-01T09:12") == 1780305120


def test_c3a7e004():
    """A date with seconds is interpreted in UTC."""
    assert parse_date_to_epoch("2026-06-01 09:12:00") == 1780305120


def test_c3a7e005():
    """An unrecognized date string raises ValueError."""
    with pytest.raises(ValueError):
        parse_date_to_epoch("last tuesday")
