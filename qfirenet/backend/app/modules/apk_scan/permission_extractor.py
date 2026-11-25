"""
modules/apk_scan/permission_extractor.py — Android APK Permission Extractor

PURPOSE:
  Android apps declare the permissions they need in their AndroidManifest.xml.
  When a user installs an APK, Android presents these permissions for approval.
  We extract this list programmatically using the androguard library.

HOW APK PERMISSIONS WORK:
  Every APK is a ZIP file containing (among other things) AndroidManifest.xml.
  This XML declares all permissions the app requests using:
      <uses-permission android:name="android.permission.CAMERA" />
  androguard parses this binary XML and returns the permission names as strings.

LIBRARY: androguard
  - The most mature Python library for static Android APK analysis.
  - APK class handles the ZIP parsing + binary XML decoding.
  - We only use it for permission extraction here (it can also do DEX bytecode
    analysis, but that's out of scope for this MVP).

IMPORTANT — SAFETY NOTE:
  We process the APK file in memory (androguard never executes the APK).
  This is STATIC analysis only — no code is run from the APK.
  The temp file is deleted by the router after extraction is complete.
"""

try:
    # androguard v4 moved the APK class to a new module path
    from androguard.core.apk import APK
except ImportError:
    # Fallback for older v3 installations
    # pyrefly: ignore [missing-import]
    from androguard.core.bytecodes.apk import APK


def extract_permissions(apk_file_path: str) -> dict:
    """
    Extract the list of declared permissions from an Android APK file.

    Parameters
    ----------
    apk_file_path : str
        Absolute path to the APK file saved temporarily on disk.
        The calling router is responsible for cleaning up this file.

    Returns
    -------
    dict with keys:
        permissions     (list[str]) — Full permission names, e.g.
                                      ["android.permission.CAMERA", ...]
        package_name    (str)       — The app's unique package identifier.
        app_name        (str)       — The declared application label.
        min_sdk_version (str)       — Minimum Android SDK version required.
        target_sdk      (str)       — Target SDK version (security relevance:
                                      older targets may lack modern protections).
        permission_count (int)      — Total number of permissions declared.
        error           (str)       — Set if extraction failed; other keys may be None.
    """
    try:
        # ── Parse the APK file ────────────────────────────────────────────────
        # APK() reads the file, validates it's a valid APK, and parses the
        # AndroidManifest.xml. This is purely read-only / static analysis.
        apk = APK(apk_file_path)

        # ── Extract declared permissions ──────────────────────────────────────
        # get_permissions() returns a list of permission strings from
        # AndroidManifest.xml's <uses-permission> elements.
        permissions = apk.get_permissions()

        # ── Extract metadata for context ──────────────────────────────────────
        package_name    = apk.get_package()       or "Unknown"
        app_name        = apk.get_app_name()      or "Unknown"
        min_sdk         = apk.get_min_sdk_version() or "Unknown"
        target_sdk      = apk.get_target_sdk_version() or "Unknown"

        return {
            "permissions":      list(permissions),
            "package_name":     package_name,
            "app_name":         app_name,
            "min_sdk_version":  min_sdk,
            "target_sdk":       target_sdk,
            "permission_count": len(permissions),
        }

    except Exception as exc:
        # Return a graceful error dict — the router handles this and still
        # produces a partial result rather than crashing.
        return {
            "permissions":      [],
            "package_name":     None,
            "app_name":         None,
            "min_sdk_version":  None,
            "target_sdk":       None,
            "permission_count": 0,
            "error":            str(exc),
        }
