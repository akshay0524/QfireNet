"""
modules/email_scan/ocr_extractor.py — Screenshot-to-Text OCR Pipeline

PURPOSE:
  When a user uploads a screenshot of an email (PNG/JPG), this module:
    1. Opens and pre-processes the image (grayscale + contrast boost + sharpening).
    2. Runs OCR (Pytesseract / Tesseract or EasyOCR) to extract text.
    3. Validates OCR quality — garbled/empty output is caught before reaching the LLM.
    4. Heuristically parses extracted text into structured fields:
       sender_email, subject, and body.
"""

import logging
import os
import re
import shutil
import string
from io import BytesIO
from typing import Optional

from PIL import Image, ImageFilter, ImageEnhance

logger = logging.getLogger(__name__)

# ── Pytesseract check ─────────────────────────────────────────────────────────
PYTESSERACT_AVAILABLE = False
try:
    import pytesseract
    # Configure path to tesseract binary if available
    tess_bin = shutil.which("tesseract") or r"C:\Users\aksha\scoop\shims\tesseract.exe"
    if os.path.exists(tess_bin):
        pytesseract.pytesseract.tesseract_cmd = tess_bin
    
    # Configure TESSDATA_PREFIX if local Scoop directory exists
    tessdata_dir = r"C:\Users\aksha\scoop\persist\tesseract\tessdata"
    if os.path.isdir(tessdata_dir) and "TESSDATA_PREFIX" not in os.environ:
        os.environ["TESSDATA_PREFIX"] = tessdata_dir

    PYTESSERACT_AVAILABLE = True
except ImportError:
    PYTESSERACT_AVAILABLE = False

# ── EasyOCR check ─────────────────────────────────────────────────────────────
EASYOCR_AVAILABLE = False
try:
    import easyocr
    import numpy as np
    EASYOCR_AVAILABLE = True
except ImportError:
    EASYOCR_AVAILABLE = False

# ── Quality thresholds ────────────────────────────────────────────────────────
MIN_TEXT_LENGTH       = 15      # Minimum readable characters (reduced to support short email snippets)
MIN_PRINTABLE_RATIO   = 0.50    # At least 50% printable ASCII chars
MIN_ALPHA_RATIO       = 0.20    # At least 20% alphabetic chars
MAX_IMAGE_BYTES       = 5 * 1024 * 1024   # 5 MB

_easyocr_reader = None


def _get_easyocr_reader():
    """Return cached EasyOCR reader if available."""
    global _easyocr_reader
    if _easyocr_reader is None and EASYOCR_AVAILABLE:
        _easyocr_reader = easyocr.Reader(["en"], gpu=False, verbose=False)
    return _easyocr_reader


def _preprocess_image(image_bytes: bytes) -> Image.Image:
    """
    Apply image preprocessing to improve OCR accuracy.

    Steps:
      1. Convert to grayscale — OCR works on luminance, not colour.
      2. Enhance contrast — boosts faint text on light/dark backgrounds.
      3. Sharpen — helps with screenshots of anti-aliased web fonts.
    """
    img = Image.open(BytesIO(image_bytes)).convert("L")   # Grayscale
    img = ImageEnhance.Contrast(img).enhance(2.0)         # Boost contrast
    img = img.filter(ImageFilter.SHARPEN)                 # Sharpen edges
    return img


def _validate_ocr_quality(text: str) -> tuple[bool, str]:
    """
    Validate that extracted OCR text is usable for LLM analysis.

    Returns (is_valid: bool, reason: str).
    reason is empty string when valid.
    """
    cleaned = text.strip()
    if not cleaned or len(cleaned) < MIN_TEXT_LENGTH:
        return False, (
            f"OCR extracted very little text ({len(cleaned)} characters). "
            "The image may be blank, too low-resolution, or contain no readable text."
        )

    total_chars = len(cleaned)
    printable_count = sum(1 for c in cleaned if c in string.printable)
    alpha_count = sum(1 for c in cleaned if c.isalpha())

    printable_ratio = printable_count / total_chars
    alpha_ratio = alpha_count / total_chars

    if printable_ratio < MIN_PRINTABLE_RATIO:
        return False, (
            f"OCR output appears garbled (only {printable_ratio:.0%} printable characters). "
            "Try uploading a higher-quality, higher-contrast screenshot."
        )

    if alpha_ratio < MIN_ALPHA_RATIO:
        return False, (
            f"OCR output contains too few alphabetic characters ({alpha_ratio:.0%}). "
            "The image may not contain readable email text."
        )

    return True, ""


def _parse_structured_fields(text: str) -> dict:
    """
    Heuristically extract sender_email, subject, and body from raw OCR text.
    """
    lines = text.splitlines()
    sender_email: Optional[str] = None
    subject: Optional[str] = None
    body_start_line: int = 0

    from_patterns    = [r"^from\s*:\s*(.+)$", r"^sender\s*:\s*(.+)$"]
    subject_patterns = [r"^subject\s*:\s*(.+)$", r"^re\s*:\s*(.+)$", r"^fwd?\s*:\s*(.+)$"]

    header_zone_end = min(25, len(lines))

    for i, line in enumerate(lines[:header_zone_end]):
        line_stripped = line.strip()
        line_lower    = line_stripped.lower()

        # Try From/Sender
        if sender_email is None:
            for pat in from_patterns:
                m = re.match(pat, line_lower)
                if m:
                    colon_idx = line_lower.find(":")
                    raw_value = line_stripped[colon_idx + 1:].strip() if colon_idx != -1 else line_stripped
                    email_match = re.search(r"[\w.+-]+@[\w.-]+\.\w{2,}", raw_value)
                    sender_email = email_match.group(0) if email_match else raw_value
                    body_start_line = max(body_start_line, i + 1)
                    break

        # Try Subject
        if subject is None:
            for pat in subject_patterns:
                m = re.match(pat, line_lower)
                if m:
                    colon_idx = line_lower.find(":")
                    subject = line_stripped[colon_idx + 1:].strip() if colon_idx != -1 else line_stripped
                    body_start_line = max(body_start_line, i + 1)
                    break

        if line_stripped == "" and (sender_email or subject) and i > 2:
            body_start_line = i + 1
            break

    body_lines = lines[body_start_line:]
    body = "\n".join(body_lines).strip()

    if len(body) < 30:
        body = text.strip()

    return {
        "sender_email": sender_email or "",
        "subject":      subject or "",
        "body":         body,
    }


def extract_email_from_image(image_bytes: bytes) -> dict:
    """
    Main entry point: run OCR on an image and return structured email fields.
    """
    # ── Size check ─────────────────────────────────────────────────────────────
    if len(image_bytes) > MAX_IMAGE_BYTES:
        raise ValueError(
            f"Image is too large ({len(image_bytes) / 1024 / 1024:.1f} MB). "
            "Maximum allowed size is 5 MB."
        )

    # ── Check OCR engine availability ──────────────────────────────────────────
    if not PYTESSERACT_AVAILABLE and not EASYOCR_AVAILABLE:
        raise RuntimeError(
            "OCR dependencies are not installed. "
            "Please install pytesseract (or easyocr) on the backend server."
        )

    # ── Image preprocessing ───────────────────────────────────────────────────
    try:
        prep_img = _preprocess_image(image_bytes)
    except Exception as exc:
        raise ValueError(
            f"Could not open image: {exc}. "
            "Please upload a valid PNG, JPG, or JPEG file."
        ) from exc

    # ── OCR extraction ────────────────────────────────────────────────────────
    raw_text = ""
    ocr_method = "unavailable"

    # 1. Try pytesseract (Fast, lightweight local binary)
    if PYTESSERACT_AVAILABLE:
        try:
            raw_text = pytesseract.image_to_string(prep_img)
            ocr_method = "pytesseract"
        except Exception as t_err:
            logger.warning(f"pytesseract failed: {t_err}")

    # 2. Try easyocr as fallback if pytesseract returned nothing
    if not raw_text.strip() and EASYOCR_AVAILABLE:
        try:
            reader = _get_easyocr_reader()
            if reader:
                img_rgb = np.array(prep_img.convert("RGB"))
                results = reader.readtext(img_rgb, detail=0, paragraph=True)
                raw_text = "\n".join(results)
                ocr_method = "easyocr"
        except Exception as e_err:
            logger.warning(f"EasyOCR failed: {e_err}")

    if not raw_text.strip():
        # Fallback: try raw un-preprocessed PIL Image with pytesseract
        if PYTESSERACT_AVAILABLE:
            try:
                raw_img = Image.open(BytesIO(image_bytes))
                raw_text = pytesseract.image_to_string(raw_img)
                ocr_method = "pytesseract"
            except Exception:
                pass

    if not raw_text.strip():
        raise ValueError(
            "No readable text could be extracted from the screenshot. "
            "Please ensure the image contains clear, non-blurry text."
        )

    # ── Quality validation ────────────────────────────────────────────────────
    is_valid, reason = _validate_ocr_quality(raw_text)
    if not is_valid:
        raise ValueError(reason)

    # ── Structured field extraction ───────────────────────────────────────────
    fields = _parse_structured_fields(raw_text)
    fields["raw_text"]   = raw_text
    fields["ocr_method"] = ocr_method

    return fields
