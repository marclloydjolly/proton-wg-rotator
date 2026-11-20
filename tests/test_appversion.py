"""Self-healing app-version probe logic."""
from protonwg.appversion import ver_tuple, candidate_versions, VERSION_REJECTED_MARKERS


def test_ver_tuple_parses_and_orders():
    assert ver_tuple("linux-vpn@4.19.1") == (4, 19, 1)
    assert ver_tuple("garbage") == ()
    assert ver_tuple("linux-vpn@4.20.0") > ver_tuple("linux-vpn@4.19.9")


def test_candidates_cover_next_patch_and_minor():
    c = candidate_versions("linux-vpn@4.19.1")
    assert c[0] == "linux-vpn@4.19.2"          # next patch probed first
    assert "linux-vpn@4.20.0" in c             # and the next minor
    assert "linux-vpn@4.19.1" not in c         # never re-probe the rejected one
    assert all(ver_tuple(v) > (4, 19, 1) for v in c)  # every candidate strictly newer


def test_candidates_handle_unparseable():
    assert candidate_versions("weird-no-at") == []


def test_markers():
    assert "no longer supported" in VERSION_REJECTED_MARKERS
