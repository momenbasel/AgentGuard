"""Tests for typosquatting detection."""

from agentguard.checks.typosquat import TyposquatChecker, _levenshtein
from agentguard.parsers import PackageRef


def test_levenshtein_identical():
    assert _levenshtein("lodash", "lodash") == 0


def test_levenshtein_one_char():
    assert _levenshtein("lodash", "lodahs") == 2  # transposition = 2 substitutions in basic impl
    assert _levenshtein("lodash", "lodasx") == 1


def test_levenshtein_insertion():
    assert _levenshtein("lodash", "loddash") == 1


def test_levenshtein_deletion():
    assert _levenshtein("lodash", "lodas") == 1


def test_exact_match_not_suspect():
    checker = TyposquatChecker()
    pkg = PackageRef(manager="npm", name="lodash")
    result = checker.check(pkg)
    assert not result.is_suspect


def test_typosquat_detected():
    checker = TyposquatChecker(threshold=2)
    pkg = PackageRef(manager="npm", name="lodasx")
    result = checker.check(pkg)
    assert result.is_suspect
    assert result.target_package == "lodash"


def test_completely_different_not_flagged():
    checker = TyposquatChecker(threshold=2)
    pkg = PackageRef(manager="npm", name="my-unique-package-xyz")
    result = checker.check(pkg)
    assert not result.is_suspect


def test_scoped_package_exact():
    checker = TyposquatChecker()
    pkg = PackageRef(manager="npm", name="core", scope="@angular")
    result = checker.check(pkg)
    assert not result.is_suspect


def test_scope_confusion_detected():
    checker = TyposquatChecker()
    # A scope typosquat of @angular - detected via edit distance or scope check
    pkg = PackageRef(manager="npm", name="core", scope="@angullar")
    result = checker.check(pkg)
    assert result.is_suspect
    assert result.attack_type in ("scope_typosquat", "insertion")


def test_pip_exact_match():
    checker = TyposquatChecker()
    pkg = PackageRef(manager="pip", name="requests")
    result = checker.check(pkg)
    assert not result.is_suspect


def test_pip_typosquat():
    checker = TyposquatChecker(threshold=2)
    pkg = PackageRef(manager="pip", name="reqeusts")
    result = checker.check(pkg)
    assert result.is_suspect
