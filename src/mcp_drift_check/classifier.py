import re
from pathlib import Path

EXACT_SEMVER = re.compile(r"^v?\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$")
RANGE_MARKERS = ("^", "~", ">", "<", "=", "*", "x", "X", "||", " - ")

def split_package_spec(spec: str):
    spec = spec.strip()
    if not spec:
        return None, None
    if spec.startswith('@'):
        slash = spec.find('/')
        if slash < 0:
            return spec, None
        at = spec.rfind('@')
        if at > slash:
            return spec[:at], spec[at+1:] or None
        return spec, None
    if '@' in spec:
        name, version = spec.rsplit('@', 1)
        return name, version or None
    return spec, None

def classify_package(spec: str, auto_yes: bool = False):
    package, version = split_package_spec(spec)
    suffix = " The invocation also uses -y/--yes, reducing interactive confirmation." if auto_yes else ""
    if not package:
        return None, None, "REVIEW", "Package reference could not be parsed.", "Review the command manually."
    if version is None:
        return package, None, "HIGH", "Package version is not pinned; future resolution may select different package code." + suffix, f"Pin {package} to a reviewed exact version."
    if version.lower() == 'latest':
        return package, version, "HIGH", "Package explicitly uses @latest; future resolution may select different package code." + suffix, f"Replace @latest with a reviewed exact version for {package}."
    if EXACT_SEMVER.fullmatch(version):
        return package, version, "SAFE", "Package is pinned to an exact semantic version.", "Keep the reviewed exact version pinned and update intentionally."
    if any(m in version for m in RANGE_MARKERS) or not EXACT_SEMVER.fullmatch(version):
        return package, version, "MEDIUM", "Package uses a non-exact version selector; resolution may change within the allowed selector." + suffix, f"Pin {package} to a reviewed exact version."
    return package, version, "REVIEW", "Package version could not be classified confidently.", "Review the package selector manually."

def classify_non_package(command: str):
    expanded = str(Path(command).expanduser())
    if command.startswith(('/', './', '../', '~')) or '/' in command:
        return "REVIEW", "Local or path-based executable; package drift rules do not apply directly.", "Verify the executable path, ownership, and update process."
    return "REVIEW", "Command is not a supported package-runner invocation and was not executed.", "Review how this command is installed and updated."


# --- uvx / PEP 508 package references (zero execution) ---

_UVX_URL_PREFIXES = ("http://", "https://", "git+", "file:", "ssh://", "ftp://")
_UVX_LOCAL_PREFIXES = ("./", "../", "/", "~", "\\")
# name[extra] followed by the version specifier; environment markers are stripped first
_PEP508_REQ = re.compile(r"^([A-Za-z0-9._-]+)(\[[^\]]*\])?\s*(.*?)\s*$")
_PEP508_CLAUSE = re.compile(r"^(===|==|~=|>=|<=|!=|>|<)\s*(\S(?:.*\S)?)\s*$")


def _split_pep508(spec):
    """Return (name, version_specifier or None) for a PEP 508 requirement.

    Extras (``pkg[extra]``) and environment markers (``; python_version > "3"``)
    are stripped; the caller classifies the remaining specifier. Returns
    (None, None) when the requirement does not parse as ``name[extra] spec``.
    """
    req = spec.split(";", 1)[0].strip()
    m = _PEP508_REQ.match(req)
    if not m:
        return None, None
    name, _, version_part = m.groups()
    version_part = (version_part or "").strip()
    return name, version_part or None


def classify_uvx_spec(spec: str):
    """Classify a static ``uvx`` package reference without executing anything.

    Returns (package, version, level, reason, recommendation), mirroring
    :func:`classify_package`. PEP 508 version specifiers are honoured:
    ``==``/``===`` pins are SAFE, ranges are MEDIUM, bare names are HIGH.
    URLs, local paths and wheels are REVIEW rather than registry references.
    Non-PEP-508 selectors such as ``pkg@1.2.3`` are REVIEW as intentionally
    unsupported instead of being guessed at.
    """
    spec = spec.strip()
    if not spec:
        return None, None, "REVIEW", "uvx package reference could not be parsed.", "Review the command manually."
    lowered = spec.lower()
    if lowered.startswith(_UVX_URL_PREFIXES) or "://" in spec:
        return spec, None, "REVIEW", "uvx reference is a URL, not a registry package; drift rules do not apply directly.", "Review the URL source manually; no package was downloaded."
    if spec.startswith(_UVX_LOCAL_PREFIXES) or lowered.endswith(".whl"):
        return spec, None, "REVIEW", "uvx reference is a local path or wheel file, not a registry package.", "Verify the local file's provenance and update process."
    if "@" in spec:
        return spec, None, "REVIEW", "uvx reference uses '@', which is not a PEP 508 version selector; the intended version is ambiguous.", "Rewrite with a PEP 508 specifier (for example pkg==1.2.3) or review manually."
    name, version_part = _split_pep508(spec)
    if not name:
        return None, None, "REVIEW", "uvx package reference could not be parsed.", "Review the command manually."
    if version_part is None:
        return name, None, "HIGH", "Package version is not pinned; future resolution may select different package code.", f"Pin {name} to a reviewed exact version (for example {name}==1.2.3)."
    clauses = [c.strip() for c in version_part.split(",") if c.strip()]
    parsed = []
    for clause in clauses:
        m = _PEP508_CLAUSE.match(clause)
        if not m:
            return name, version_part, "REVIEW", f"Version selector '{clause}' is not a recognized PEP 508 specifier.", "Review the selector manually; no package was downloaded."
        parsed.append((m.group(1), m.group(2)))
    if len(parsed) == 1 and parsed[0][0] in ("==", "==="):
        pinned = parsed[0][1]
        if "*" in pinned:
            return name, version_part, "MEDIUM", "Package uses a wildcard version selector; resolution may change within the allowed prefix.", f"Pin {name} to a reviewed exact version."
        return name, version_part, "SAFE", "Package is pinned to an exact version.", "Keep the reviewed exact version pinned and update intentionally."
    return name, version_part, "MEDIUM", "Package uses a non-exact version selector; resolution may change within the allowed selector.", f"Pin {name} to a reviewed exact version."
