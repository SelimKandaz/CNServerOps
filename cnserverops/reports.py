"""Dependency-light human report generation for the production SSD.

The writers intentionally use only the Python standard library so an immutable
runtime can generate XLSX, PDF, HTML, and JSON reports without a desktop stack.
"""

from __future__ import annotations

import hashlib
import html
import json
import os
import re
import tempfile
import zipfile
import posixpath
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence
from xml.sax.saxutils import escape as xml_escape

from .inventory_model import physical_nic_rows, serial_rows
from .secrets import assert_no_sensitive_fields


class XlsxValidationError(ValueError):
    """Raised when a generated OOXML workbook is not structurally usable."""


_XLSX_MAIN_NS = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
_XLSX_REL_NS = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
_XLSX_PACKAGE_REL_NS = "http://schemas.openxmlformats.org/package/2006/relationships"
_XLSX_NS = {"main": _XLSX_MAIN_NS, "r": _XLSX_REL_NS, "pr": _XLSX_PACKAGE_REL_NS}

# Excel expects a theme relationship even when the workbook only uses explicit
# RGB colours.  Keeping a small standards-compliant theme here avoids a
# dependency on openpyxl/XlsxWriter in the immutable SSD runtime.
_XLSX_THEME_XML = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<a:theme xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" name="Office Theme"><a:themeElements><a:clrScheme name="Office"><a:dk1><a:sysClr val="windowText" lastClr="000000"/></a:dk1><a:lt1><a:sysClr val="window" lastClr="FFFFFF"/></a:lt1><a:dk2><a:srgbClr val="1F497D"/></a:dk2><a:lt2><a:srgbClr val="EEECE1"/></a:lt2><a:accent1><a:srgbClr val="4F81BD"/></a:accent1><a:accent2><a:srgbClr val="C0504D"/></a:accent2><a:accent3><a:srgbClr val="9BBB59"/></a:accent3><a:accent4><a:srgbClr val="8064A2"/></a:accent4><a:accent5><a:srgbClr val="4BACC6"/></a:accent5><a:accent6><a:srgbClr val="F79646"/></a:accent6><a:hlink><a:srgbClr val="0000FF"/></a:hlink><a:folHlink><a:srgbClr val="800080"/></a:folHlink></a:clrScheme><a:fontScheme name="Office"><a:majorFont><a:latin typeface="Cambria"/><a:ea typeface=""/><a:cs typeface=""/></a:majorFont><a:minorFont><a:latin typeface="Calibri"/><a:ea typeface=""/><a:cs typeface=""/></a:minorFont></a:fontScheme><a:fmtScheme name="Office"><a:fillStyleLst><a:solidFill><a:schemeClr val="phClr"/></a:solidFill><a:solidFill><a:schemeClr val="phClr"/></a:solidFill><a:solidFill><a:schemeClr val="phClr"/></a:solidFill></a:fillStyleLst><a:lnStyleLst><a:ln w="9525"><a:solidFill><a:schemeClr val="phClr"/></a:solidFill><a:prstDash val="solid"/></a:ln><a:ln w="25400"><a:solidFill><a:schemeClr val="phClr"/></a:solidFill><a:prstDash val="solid"/></a:ln><a:ln w="38100"><a:solidFill><a:schemeClr val="phClr"/></a:solidFill><a:prstDash val="solid"/></a:ln></a:lnStyleLst><a:effectStyleLst><a:effectStyle><a:effectLst/></a:effectStyle><a:effectStyle><a:effectLst/></a:effectStyle><a:effectStyle><a:effectLst/></a:effectStyle></a:effectStyleLst><a:bgFillStyleLst><a:solidFill><a:schemeClr val="phClr"/></a:solidFill><a:solidFill><a:schemeClr val="phClr"/></a:solidFill><a:solidFill><a:schemeClr val="phClr"/></a:solidFill></a:bgFillStyleLst></a:fmtScheme></a:themeElements><a:objectDefaults/><a:extraClrSchemeLst/></a:theme>"""


def _xlsx_content_types(sheet_count: int) -> str:
    sheet_overrides = "".join(
        f'<Override PartName="/xl/worksheets/sheet{index}.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
        for index in range(1, sheet_count + 1)
    )
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
        f'{sheet_overrides}'
        '<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>'
        '<Override PartName="/xl/theme/theme1.xml" ContentType="application/vnd.openxmlformats-officedocument.theme+xml"/>'
        '<Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>'
        '<Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/>'
        '</Types>'
    )


def _xlsx_root_relationships() -> str:
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml" Id="rId1"/>'
        '<Relationship Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml" Id="rId2"/>'
        '<Relationship Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties" Target="docProps/app.xml" Id="rId3"/>'
        '</Relationships>'
    )


def _xlsx_workbook_relationships(sheet_count: int) -> str:
    sheets = "".join(
        f'<Relationship Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="/xl/worksheets/sheet{index}.xml" Id="rId{index}"/>'
        for index in range(1, sheet_count + 1)
    )
    style_id = sheet_count + 1
    theme_id = sheet_count + 2
    return (
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        f'{sheets}'
        f'<Relationship Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml" Id="rId{style_id}"/>'
        f'<Relationship Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/theme" Target="theme/theme1.xml" Id="rId{theme_id}"/>'
        '</Relationships>'
    )


def _xlsx_workbook_xml(sheet_names: Sequence[str]) -> str:
    sheets = "".join(
        f'<sheet name="{_xml_text(name)}" sheetId="{index}" state="visible" r:id="rId{index}"/>'
        for index, name in enumerate(sheet_names, start=1)
    )
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
        'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
        '<workbookPr/><workbookProtection/>'
        '<bookViews><workbookView visibility="visible" minimized="0" showHorizontalScroll="1" showVerticalScroll="1" showSheetTabs="1" tabRatio="600" firstSheet="0" activeTab="0" autoFilterDateGrouping="1"/></bookViews>'
        f'<sheets>{sheets}</sheets><definedNames/><calcPr calcId="124519" fullCalcOnLoad="1"/>'
        '</workbook>'
    )


def _xlsx_core_properties(title: str) -> str:
    now = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
        f'<dc:title>{_xml_text(title)}</dc:title><dc:creator>CNServerOps</dc:creator><cp:lastModifiedBy>CNServerOps</cp:lastModifiedBy>'
        f'<dcterms:created xsi:type="dcterms:W3CDTF">{now}</dcterms:created><dcterms:modified xsi:type="dcterms:W3CDTF">{now}</dcterms:modified>'
        '</cp:coreProperties>'
    )


def _xlsx_app_properties() -> str:
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties"><Application>CNServerOps</Application><AppVersion>1.0</AppVersion></Properties>'
    )


_STATUS_PASS = {"PASS", "PASSED", "SUCCESS", "SYNCED", "CURRENT", "UPDATED_VERIFIED", "READY_FOR_HANDOFF", "READY_FOR_SALE"}
_STATUS_REVIEW = {
    "REVIEW",
    "REVIEW_REQUIRED",
    "BLOCKED_BY_AUTH",
    "UNVERIFIED",
    "NOT_SUPPORTED",
    "NOT_TESTED",
    "NOT_PERFORMED",
    "PENDING_UPLOAD",
    "PARTIAL",
}
_STATUS_FAIL = {"FAIL", "FAILED", "BLOCKED", "NOT_READY", "NOT_READY_FOR_SALE", "NOT_READY_FOR_HANDOFF", "UPLOAD_FAILED"}


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _safe_token(value: Any, fallback: str) -> str:
    text = re.sub(r"[^A-Za-z0-9._-]+", "-", str(value or "").strip()).strip("-._")
    return (text or fallback)[:96]


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def validate_xlsx(
    path: Path,
    *,
    expected_sheets: Sequence[str],
    required_values: Sequence[str] = (),
) -> dict[str, Any]:
    """Re-open and validate a finalized XLSX package using the OOXML parts.

    This deliberately stays dependency-free for the SSD runtime while checking
    the same ZIP/XML relationships that Excel uses to locate sheets and cells.
    """
    if path.is_symlink() or not path.is_file():
        raise XlsxValidationError(f"XLSX is not a regular file: {path.name}")
    try:
        with zipfile.ZipFile(path, "r") as archive:
            if archive.testzip() is not None:
                raise XlsxValidationError(f"XLSX ZIP CRC check failed: {path.name}")
            names = set(archive.namelist())
            required_parts = {
                "[Content_Types].xml",
                "_rels/.rels",
                "xl/workbook.xml",
                "xl/_rels/workbook.xml.rels",
                "xl/styles.xml",
            }
            missing = sorted(required_parts - names)
            if missing:
                raise XlsxValidationError(f"XLSX required parts are missing: {', '.join(missing)}")
            roots: dict[str, ET.Element] = {}
            for member in names:
                if member.endswith(".xml") or member.endswith(".rels"):
                    try:
                        roots[member] = ET.fromstring(archive.read(member))
                    except ET.ParseError as exc:
                        raise XlsxValidationError(f"XLSX XML parse failed in {member}") from exc
            workbook = roots["xl/workbook.xml"]
            workbook_rels = roots["xl/_rels/workbook.xml.rels"]
            relationships = {
                str(item.get("Id")): str(item.get("Target") or "")
                for item in workbook_rels.findall("pr:Relationship", _XLSX_NS)
            }
            sheet_names: list[str] = []
            observed_values: set[str] = set()
            for sheet in workbook.findall("main:sheets/main:sheet", _XLSX_NS):
                name = str(sheet.get("name") or "")
                sheet_names.append(name)
                relationship_id = sheet.get(f"{{{_XLSX_REL_NS}}}id") or ""
                target = relationships.get(relationship_id)
                if not target:
                    raise XlsxValidationError(f"XLSX sheet relationship is missing: {name}")
                sheet_part = (
                    posixpath.normpath(target.lstrip("/"))
                    if target.startswith("/")
                    else posixpath.normpath(posixpath.join("xl", target))
                )
                if sheet_part not in names or not sheet_part.startswith("xl/"):
                    raise XlsxValidationError(f"XLSX sheet target is missing: {name}")
                sheet_root = roots.get(sheet_part)
                if sheet_root is None:
                    sheet_root = ET.fromstring(archive.read(sheet_part))
                for cell in sheet_root.findall(".//main:c", _XLSX_NS):
                    inline = cell.find("main:is", _XLSX_NS)
                    if inline is not None:
                        observed_values.add("".join(inline.itertext()))
                    value = cell.find("main:v", _XLSX_NS)
                    if value is not None and value.text:
                        observed_values.add(value.text)
            expected = list(expected_sheets)
            if sheet_names != expected:
                raise XlsxValidationError(f"XLSX sheet names mismatch: expected {expected}, got {sheet_names}")
            missing_values = [value for value in required_values if str(value) not in observed_values]
            if missing_values:
                raise XlsxValidationError(f"XLSX required cell values are missing: {missing_values}")
            return {
                "status": "VALID",
                "format": "OOXML_XLSX",
                "zip_crc": "PASS",
                "sheets": sheet_names,
                "required_values_verified": [str(value) for value in required_values],
                "size_bytes": path.stat().st_size,
                "sha256": _sha256(path),
            }
    except zipfile.BadZipFile as exc:
        raise XlsxValidationError(f"XLSX is not a readable ZIP package: {path.name}") from exc


REQUIRED_REPORT_TYPES = (
    "SERIALS_XLSX",
    "HARDWARE_INVENTORY_XLSX",
    "PRODUCTION_PDF",
    "FIRMWARE_PROOF_PDF",
    "DIAGNOSTIC_HTML",
)


def report_manifest_complete(
    manifest: Mapping[str, Any] | None,
    *,
    extended_diagnostics: bool = False,
) -> bool:
    """Return whether the human report set is complete and locally final.

    Artifact count is intentionally not used: workflows may add raw evidence,
    SEL logs, or an extended-diagnostics PDF.  Completeness is based on the
    required semantic artifact types and their finalized/hash-verified state.
    """
    if not isinstance(manifest, Mapping):
        return False
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, Sequence) or isinstance(artifacts, (str, bytes, bytearray)):
        return False
    by_type: dict[str, Mapping[str, Any]] = {}
    for item in artifacts:
        if not isinstance(item, Mapping):
            continue
        artifact_type = str(item.get("type") or "").strip().upper()
        if artifact_type and artifact_type not in by_type:
            by_type[artifact_type] = item
    required = list(REQUIRED_REPORT_TYPES)
    if extended_diagnostics:
        required.append("EXTENDED_DIAGNOSTICS_PDF")
    for artifact_type in required:
        item = by_type.get(artifact_type)
        if item is None or str(item.get("state") or "").upper() != "LOCAL_COMPLETE":
            return False
        if not str(item.get("path") or "").strip() or not str(item.get("name") or "").strip():
            return False
        digest = str(item.get("sha256") or "").lower()
        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            return False
        try:
            if int(item.get("size_bytes") or 0) <= 0:
                return False
        except (TypeError, ValueError):
            return False
        if artifact_type.endswith("_XLSX"):
            validation = item.get("validation")
            if not isinstance(validation, Mapping) or str(validation.get("status") or "").upper() != "VALID":
                return False
    return True


def _publish_validated_xlsx(
    temporary: Path,
    destination: Path,
    *,
    expected_sheets: Sequence[str],
    required_values: Sequence[str],
) -> dict[str, Any]:
    """Validate a closed temporary workbook, atomically publish, and re-open it."""
    validation = validate_xlsx(
        temporary, expected_sheets=expected_sheets, required_values=required_values
    )
    with temporary.open("r+b") as stream:
        stream.flush()
        os.fsync(stream.fileno())
    temporary.replace(destination)
    try:
        return validate_xlsx(
            destination, expected_sheets=expected_sheets, required_values=required_values
        )
    except Exception:
        destination.unlink(missing_ok=True)
        raise


def _status(value: Any, default: str = "UNKNOWN") -> str:
    return str(value or default).strip().upper().replace(" ", "_")


def _status_style(value: Any) -> int:
    normalized = _status(value)
    if normalized in _STATUS_PASS:
        return 5
    if normalized in _STATUS_FAIL:
        return 7
    if normalized in _STATUS_REVIEW:
        return 6
    return 8


def _display(value: Any, fallback: str = "-") -> str:
    if value is None:
        return fallback
    if isinstance(value, bool):
        return "YES" if value else "NO"
    if isinstance(value, (dict, list, tuple)):
        return json.dumps(value, sort_keys=True, ensure_ascii=True)
    text = " ".join(str(value).replace("\x00", " ").split())
    return text or fallback


def _xml_text(value: Any) -> str:
    text = _display(value, "")
    text = "".join(character for character in text if character in "\t\n\r" or ord(character) >= 32)
    return xml_escape(text, {'"': "&quot;"})


def _column_name(index: int) -> str:
    value = index + 1
    result = ""
    while value:
        value, remainder = divmod(value - 1, 26)
        result = chr(65 + remainder) + result
    return result


@dataclass(frozen=True)
class XlsxCell:
    value: Any
    style: int = 4


def _xlsx_row_xml(row_number: int, values: Sequence[Any], styles: Sequence[int] | None = None) -> str:
    cells: list[str] = []
    for index, raw in enumerate(values):
        value = raw.value if isinstance(raw, XlsxCell) else raw
        style = raw.style if isinstance(raw, XlsxCell) else (styles[index] if styles and index < len(styles) else 4)
        reference = f"{_column_name(index)}{row_number}"
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            cells.append(f'<c r="{reference}" s="{style}" t="n"><v>{value}</v></c>')
        else:
            preserve = ' xml:space="preserve"' if str(value or "").startswith(" ") or str(value or "").endswith(" ") else ""
            cells.append(
                f'<c r="{reference}" s="{style}" t="inlineStr"><is><t{preserve}>{_xml_text(value)}</t></is></c>'
            )
    return f'<row r="{row_number}">{"".join(cells)}</row>'


def _sheet_xml(
    rows: Sequence[Sequence[Any]],
    *,
    widths: Sequence[float],
    freeze_row: int,
    auto_filter: str = "",
    merges: Sequence[str] = (),
) -> str:
    max_columns = max((len(row) for row in rows), default=1)
    dimension = f"A1:{_column_name(max_columns - 1)}{max(1, len(rows))}"
    columns = "".join(
        f'<col min="{index + 1}" max="{index + 1}" width="{width}" customWidth="1"/>'
        for index, width in enumerate(widths)
    )
    pane = (
        f'<pane ySplit="{freeze_row}" topLeftCell="A{freeze_row + 1}" activePane="bottomLeft" state="frozen"/>'
        if freeze_row
        else ""
    )
    merge_xml = (
        f'<mergeCells count="{len(merges)}">'
        + "".join(f'<mergeCell ref="{_xml_text(item)}"/>' for item in merges)
        + "</mergeCells>"
        if merges
        else ""
    )
    filter_xml = f'<autoFilter ref="{_xml_text(auto_filter)}"/>' if auto_filter else ""
    body = "".join(_xlsx_row_xml(index, row) for index, row in enumerate(rows, start=1))
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        f'<dimension ref="{dimension}"/><sheetViews><sheetView showGridLines="0" workbookViewId="0">{pane}</sheetView></sheetViews>'
        '<sheetFormatPr defaultRowHeight="18"/>'
        # OOXML worksheet schema requires autoFilter before mergeCells.
        f'<cols>{columns}</cols><sheetData>{body}</sheetData>{filter_xml}{merge_xml}'
        '<pageMargins left="0.35" right="0.35" top="0.5" bottom="0.5" header="0.2" footer="0.2"/>'
        '</worksheet>'
    )


def _xlsx_styles() -> str:
    return """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
 <fonts count="4">
  <font><sz val="10"/><name val="Aptos"/><family val="2"/></font>
  <font><b/><sz val="16"/><color rgb="FFFFFFFF"/><name val="Aptos Display"/></font>
  <font><b/><sz val="10"/><color rgb="FFFFFFFF"/><name val="Aptos"/></font>
  <font><b/><sz val="10"/><color rgb="FF183153"/><name val="Aptos"/></font>
 </fonts>
 <fills count="8">
  <fill><patternFill patternType="none"/></fill><fill><patternFill patternType="gray125"/></fill>
  <fill><patternFill patternType="solid"><fgColor rgb="FF183153"/><bgColor indexed="64"/></patternFill></fill>
  <fill><patternFill patternType="solid"><fgColor rgb="FF147D92"/><bgColor indexed="64"/></patternFill></fill>
  <fill><patternFill patternType="solid"><fgColor rgb="FFE8F1F5"/><bgColor indexed="64"/></patternFill></fill>
  <fill><patternFill patternType="solid"><fgColor rgb="FFDFF3E4"/><bgColor indexed="64"/></patternFill></fill>
  <fill><patternFill patternType="solid"><fgColor rgb="FFFFF0C2"/><bgColor indexed="64"/></patternFill></fill>
  <fill><patternFill patternType="solid"><fgColor rgb="FFF9D7D7"/><bgColor indexed="64"/></patternFill></fill>
 </fills>
 <borders count="2"><border/><border><bottom style="thin"><color rgb="FFCAD6DF"/></bottom></border></borders>
 <cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>
 <cellXfs count="12">
  <xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/>
  <xf numFmtId="0" fontId="1" fillId="2" borderId="0" xfId="0" applyFont="1" applyFill="1"><alignment vertical="center"/></xf>
  <xf numFmtId="0" fontId="2" fillId="2" borderId="0" xfId="0" applyFont="1" applyFill="1"/>
  <xf numFmtId="0" fontId="2" fillId="3" borderId="0" xfId="0" applyFont="1" applyFill="1"><alignment vertical="center" wrapText="1"/></xf>
  <xf numFmtId="0" fontId="0" fillId="0" borderId="1" xfId="0" applyBorder="1"><alignment vertical="top" wrapText="1"/></xf>
  <xf numFmtId="0" fontId="3" fillId="5" borderId="1" xfId="0" applyFont="1" applyFill="1" applyBorder="1"/>
  <xf numFmtId="0" fontId="3" fillId="6" borderId="1" xfId="0" applyFont="1" applyFill="1" applyBorder="1"/>
  <xf numFmtId="0" fontId="3" fillId="7" borderId="1" xfId="0" applyFont="1" applyFill="1" applyBorder="1"/>
  <xf numFmtId="0" fontId="3" fillId="4" borderId="1" xfId="0" applyFont="1" applyFill="1" applyBorder="1"/>
  <xf numFmtId="0" fontId="3" fillId="4" borderId="0" xfId="0" applyFont="1" applyFill="1"/>
  <xf numFmtId="0" fontId="3" fillId="0" borderId="0" xfId="0" applyFont="1"/>
  <xf numFmtId="0" fontId="0" fillId="4" borderId="0" xfId="0" applyFill="1"/>
 </cellXfs>
 <cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles>
</styleSheet>"""


_SERVER_SERIAL_TEMPLATE_HEADERS = [
    "Server SN:",
    "Chassis SN:",
    "MB SN:",
    "CPU SN: ",
    "MEMORY SN: ",
    "MEM PO:",
    "NIC SN:",
    "RAID SN:",
    "NVME Adapter",
    "SSD",
    "NVME",
    "NVME 15 GB",
    "Interposer",
    "PCI-e Riser",
    "VROC SN:",
    "TPM:",
    "PSU SN:",
]


def _template_serial(value: Any) -> str:
    """Return a printable hardware serial, or blank when it is not exposed.

    This export is intentionally operator-fillable.  Unlike the authoritative
    inventory workbook, it does not print ``NOT_EXPOSED``/``UNKNOWN`` markers.
    In particular, a MAC address is never accepted as a serial fallback.
    """
    text = " ".join(str(value or "").replace("\x00", " ").split()).strip()
    if text.upper() in {"NOT_EXPOSED", "UNKNOWN", "N/A", "NONE", "-", "TO BE FILLED BY O.E.M."}:
        return ""
    return text


def _template_components(inventory: Mapping[str, Any], category: str) -> list[Mapping[str, Any]]:
    return [
        component
        for component in (inventory.get("components", []) if isinstance(inventory.get("components"), list) else [])
        if isinstance(component, Mapping) and str(component.get("category") or "").upper() == category
    ]


def _template_serial_values(components: Sequence[Mapping[str, Any]]) -> list[str]:
    # Preserve one row per discovered physical component, even when its serial
    # is unavailable, so the technician can complete the blank manually.
    return [_template_serial(component.get("serial")) for component in components]


def _template_matching_components(inventory: Mapping[str, Any], *patterns: str) -> list[Mapping[str, Any]]:
    needles = tuple(pattern.upper() for pattern in patterns)
    components = inventory.get("components", []) if isinstance(inventory.get("components"), list) else []
    matched: list[Mapping[str, Any]] = []
    for component in components:
        if not isinstance(component, Mapping):
            continue
        haystack = " ".join(
            str(component.get(field) or "")
            for field in ("category", "slot", "location", "model", "part_number")
        ).upper()
        if any(needle in haystack for needle in needles):
            matched.append(component)
    return matched


def _server_serial_template_rows(inventory: Mapping[str, Any]) -> list[list[Any]]:
    """Build the grouped, order-style rows used by the submitted templates.

    The first row carries SERVER/CHASSIS/MOTHERBOARD identity.  Subsequent rows
    carry component values only; identity cells remain blank exactly as in the
    DataBank and Hivelocity examples.
    """
    systems = _template_components(inventory, "SYSTEM")
    chassis = _template_components(inventory, "CHASSIS")
    boards = _template_components(inventory, "MOTHERBOARD")
    cpus = _template_components(inventory, "CPU")
    memories = _template_components(inventory, "MEMORY")
    nics = _template_components(inventory, "NIC/OCP")
    raid = _template_components(inventory, "RAID/HBA")
    storage = _template_components(inventory, "STORAGE")
    psus = _template_components(inventory, "PSU")

    def _is_nvme(component: Mapping[str, Any]) -> bool:
        return "NVME" in " ".join(
            str(component.get(field) or "") for field in ("interface", "model", "slot", "location")
        ).upper()

    nvme = [component for component in storage if _is_nvme(component)]
    ssd = [component for component in storage if component not in nvme]
    nvme_15gb = [
        component
        for component in nvme
        if "15 GB" in " ".join(
            str(component.get(field) or "") for field in ("model", "slot", "location", "part_number")
        ).upper()
        or (
            isinstance(component.get("capacity_bytes"), (int, float))
            and 14 * 1024**3 <= component.get("capacity_bytes", 0) <= 16 * 1024**3
        )
    ]

    columns: dict[str, list[str]] = {
        "Server SN:": [_template_serial(systems[0].get("serial"))] if systems else [_template_serial(inventory.get("system_serial"))],
        "Chassis SN:": [_template_serial(chassis[0].get("serial"))] if chassis else [""],
        "MB SN:": [_template_serial(boards[0].get("serial"))] if boards else [""],
        "CPU SN: ": _template_serial_values(cpus),
        "MEMORY SN: ": _template_serial_values(memories),
        "MEM PO:": [_template_serial(component.get("part_number")) for component in memories],
        "NIC SN:": _template_serial_values(nics),
        "RAID SN:": _template_serial_values(raid),
        "NVME Adapter": _template_serial_values(_template_matching_components(inventory, "NVME ADAPTER", "NVME CONTROLLER")),
        "SSD": _template_serial_values(ssd),
        "NVME": _template_serial_values(nvme),
        "NVME 15 GB": _template_serial_values(nvme_15gb),
        "Interposer": _template_serial_values(_template_matching_components(inventory, "INTERPOSER")),
        "PCI-e Riser": _template_serial_values(_template_matching_components(inventory, "RISER", "PCI-E RISER")),
        "VROC SN:": _template_serial_values(_template_matching_components(inventory, "VROC")),
        "TPM:": _template_serial_values(_template_matching_components(inventory, "TPM")),
        "PSU SN:": _template_serial_values(psus),
    }
    row_count = max(1, *(len(values) for values in columns.values()))
    rows: list[list[Any]] = []
    for index in range(row_count):
        row: list[Any] = []
        for header in _SERVER_SERIAL_TEMPLATE_HEADERS:
            values = columns[header]
            # Server identity is intentionally shown once.  A discovered
            # chassis/board serial is also shown once, matching the templates.
            row.append(values[index] if index < len(values) else "")
        if index > 0:
            row[0] = ""
            row[1] = ""
            row[2] = ""
        rows.append(row)
    return rows


def write_server_serial_template_workbook(path: Path, inventory: Mapping[str, Any]) -> Path:
    """Write the additional DataBank/Hivelocity-style serial workbook.

    Existing CNServerOps XLSX files are left untouched.  This workbook is a
    separate, credential-free operator template intended for final manual
    completion of fields (notably CPU serials) that hardware does not expose.
    """
    assert_no_sensitive_fields(inventory)
    system_serial = _template_serial(inventory.get("system_serial"))
    title = f"CNServerOps Server Serial Inventory - {system_serial or 'SERIAL TO BE COMPLETED'}"
    rows: list[list[Any]] = [
        [XlsxCell(title, 1)] + [XlsxCell("", 1) for _ in _SERVER_SERIAL_TEMPLATE_HEADERS[1:]],
        [XlsxCell(header, 3) for header in _SERVER_SERIAL_TEMPLATE_HEADERS],
        ["" for _ in _SERVER_SERIAL_TEMPLATE_HEADERS],
    ]
    rows.extend(_server_serial_template_rows(inventory))
    sheet = _sheet_xml(
        rows,
        widths=[20, 28, 28, 24, 26, 18, 26, 24, 24, 24, 24, 24, 24, 24, 24, 18, 24],
        freeze_row=2,
        auto_filter=f"A2:Q{len(rows)}",
        merges=["A1:Q1"],
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=path.parent)
    os.close(descriptor)
    temporary = Path(temporary_name)
    try:
        with zipfile.ZipFile(temporary, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("[Content_Types].xml", _xlsx_content_types(1))
            archive.writestr("_rels/.rels", _xlsx_root_relationships())
            archive.writestr("xl/workbook.xml", _xlsx_workbook_xml(("Server SNs",)))
            archive.writestr("xl/_rels/workbook.xml.rels", _xlsx_workbook_relationships(1))
            archive.writestr("xl/worksheets/sheet1.xml", sheet)
            archive.writestr("xl/styles.xml", _xlsx_styles())
            archive.writestr("xl/theme/theme1.xml", _XLSX_THEME_XML)
            archive.writestr("docProps/core.xml", _xlsx_core_properties("CNServerOps Server Serial Inventory"))
            archive.writestr("docProps/app.xml", _xlsx_app_properties())
        _publish_validated_xlsx(
            temporary,
            path,
            expected_sheets=("Server SNs",),
            required_values=(system_serial,) if system_serial else (),
        )
    finally:
        if temporary.exists():
            temporary.unlink()
    return path


def write_serial_workbook(path: Path, inventory: Mapping[str, Any]) -> Path:
    """Write a two-sheet Operations workbook with no credential fields."""
    assert_no_sensitive_fields(inventory)
    rows = serial_rows(inventory)
    serial_headers = [
        "Category",
        "Slot / Location",
        "Manufacturer",
        "Model",
        "Part Number",
        "Serial",
        "Firmware",
        "Health / Status",
        "Interface / Identifier",
        "Source",
        "Confidence",
        "Conflict",
    ]
    serial_sheet: list[list[Any]] = [
        [XlsxCell(f"CNServerOps Serial Inventory - {_display(inventory.get('system_serial'), 'UNKNOWN')}", 1)]
        + [XlsxCell("", 1) for _ in range(len(serial_headers) - 1)],
        [XlsxCell(f"Generated {_utc_now()} | SERVER_ID {_display(inventory.get('server_id'))} | RUN_ID {_display(inventory.get('run_id'))}", 11)]
        + [XlsxCell("", 11) for _ in range(len(serial_headers) - 1)],
        [XlsxCell(header, 3) for header in serial_headers],
    ]
    for row in rows:
        values = [
            row["category"],
            row["slot_location"],
            row["manufacturer"],
            row["model"],
            row["part_number"],
            row["serial"],
            row["firmware"],
            XlsxCell(row["health_status"], _status_style(row["health_status"])),
            row["interface_identifier"],
            row["source"],
            row["confidence"],
            row["conflict"],
        ]
        serial_sheet.append(values)
    if not rows:
        serial_sheet.append([XlsxCell("No normalized components were available.", 6)] + ["" for _ in serial_headers[1:]])

    access_summary = [
        ("System Serial", inventory.get("system_serial")),
        ("Manufacturer", inventory.get("vendor")),
        ("Model", inventory.get("model")),
        ("Primary Host MAC", inventory.get("primary_host_mac")),
        ("BMC / IPMI IP", inventory.get("bmc_ip")),
        ("BMC MAC", inventory.get("bmc_mac")),
        ("BMC Channel / Interface", inventory.get("bmc_channel")),
        ("BMC Capability State", inventory.get("bmc_auth_state")),
    ]
    nic_headers = ["Port", "Linux Interface", "Adapter Serial", "MAC", "PCI Address", "Manufacturer", "Adapter", "Part Number", "Link", "Firmware", "Source"]
    access_sheet: list[list[Any]] = [
        [XlsxCell(f"CNServerOps Server Access - {_display(inventory.get('system_serial'), 'UNKNOWN')}", 1)]
        + [XlsxCell("", 1) for _ in range(len(nic_headers) - 1)],
        [XlsxCell("Credentials are intentionally non-reportable and are never exported.", 6)]
        + [XlsxCell("", 6) for _ in range(len(nic_headers) - 1)],
    ]
    for label, value in access_summary:
        access_sheet.append([XlsxCell(label, 10), XlsxCell(_display(value), 4)] + ["" for _ in range(len(nic_headers) - 2)])
    header_row = len(access_sheet) + 2
    access_sheet.append(["" for _ in nic_headers])
    access_sheet.append([XlsxCell(header, 3) for header in nic_headers])
    nic_rows = physical_nic_rows(inventory)
    for index, row in enumerate(nic_rows, start=1):
        access_sheet.append(
            [
                row["port_label"] or f"NIC{index}",
                row["interface"],
                row["adapter_serial"],
                row["mac"],
                row["pci_address"],
                row["manufacturer"],
                row["adapter"],
                row["part_number"],
                row["link_state"],
                row["firmware"],
                row["source"],
            ]
        )
    if not nic_rows:
        access_sheet.append([XlsxCell("No physical NIC adapter was discovered.", 6)] + ["" for _ in nic_headers[1:]])

    serial_xml = _sheet_xml(
        serial_sheet,
        widths=[18, 20, 20, 36, 24, 26, 18, 18, 28, 24, 14, 34],
        freeze_row=3,
        auto_filter=f"A3:L{len(serial_sheet)}",
        merges=["A1:L1", "A2:L2"],
    )
    access_xml = _sheet_xml(
        access_sheet,
        widths=[18, 20, 24, 22, 18, 24, 38, 24, 14, 20, 26],
        freeze_row=header_row,
        auto_filter=f"A{header_row}:K{len(access_sheet)}",
        merges=["A1:K1", "A2:K2"],
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=path.parent)
    os.close(descriptor)
    temporary = Path(temporary_name)
    try:
        with zipfile.ZipFile(temporary, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("[Content_Types].xml", _xlsx_content_types(2))
            archive.writestr("_rels/.rels", _xlsx_root_relationships())
            archive.writestr("xl/workbook.xml", _xlsx_workbook_xml(("Serials", "Server Access")))
            archive.writestr("xl/_rels/workbook.xml.rels", _xlsx_workbook_relationships(2))
            archive.writestr("xl/worksheets/sheet1.xml", serial_xml)
            archive.writestr("xl/worksheets/sheet2.xml", access_xml)
            archive.writestr("xl/styles.xml", _xlsx_styles())
            archive.writestr("xl/theme/theme1.xml", _XLSX_THEME_XML)
            archive.writestr("docProps/core.xml", _xlsx_core_properties("CNServerOps Serial Inventory"))
            archive.writestr("docProps/app.xml", _xlsx_app_properties())
        _publish_validated_xlsx(
            temporary,
            path,
            expected_sheets=("Serials", "Server Access"),
            required_values=tuple(
                dict.fromkeys(
                    [str(inventory.get("system_serial") or "UNKNOWN")]
                    + [
                        str(row.get("serial"))
                        for row in rows
                        if row.get("category") == "NIC/OCP" and row.get("serial")
                    ]
                )
            ),
        )
    finally:
        if temporary.exists():
            temporary.unlink()
    return path


def write_hardware_workbook(path: Path, inventory: Mapping[str, Any]) -> Path:
    """Write a compact hardware inventory workbook for fleet intake exports."""
    assert_no_sensitive_fields(inventory)
    headers = ["Category", "Slot / Location", "Manufacturer", "Model", "Part Number", "Serial", "Firmware", "Health", "Source", "Confidence"]
    rows: list[list[Any]] = [
        [XlsxCell(f"CNServerOps Hardware Inventory - {_display(inventory.get('system_serial'), 'UNKNOWN')}", 1)] + [XlsxCell("", 1) for _ in headers[1:]],
        [XlsxCell(f"SERVER_ID {_display(inventory.get('server_id'))} | RUN_ID {_display(inventory.get('run_id'))}", 11)] + [XlsxCell("", 11) for _ in headers[1:]],
        [XlsxCell("System Serial", 10), XlsxCell(_display(inventory.get("system_serial")), 4)] + ["" for _ in headers[2:]],
        [XlsxCell(header, 3) for header in headers],
    ]
    for item in inventory.get("components", []) if isinstance(inventory.get("components"), list) else []:
        if not isinstance(item, Mapping):
            continue
        field_evidence = item.get("field_evidence") or {}
        serial_evidence = field_evidence.get("serial") if isinstance(field_evidence, Mapping) else {}
        if not isinstance(serial_evidence, Mapping):
            serial_evidence = {}
        rows.append([
            item.get("category", ""), item.get("slot", item.get("slot_location", "")), item.get("manufacturer", ""),
            item.get("model", ""), item.get("part_number", ""), item.get("serial", ""), item.get("firmware", ""),
            item.get("health", item.get("health_status", "")),
            serial_evidence.get("source", item.get("source", "")),
            serial_evidence.get("confidence", item.get("confidence", "")),
        ])
    if len(rows) == 4:
        rows.append([XlsxCell("No normalized hardware components were available.", 6)] + ["" for _ in headers[1:]])
    sheet = _sheet_xml(rows, widths=[22, 22, 22, 34, 24, 26, 18, 18, 30, 14], freeze_row=4, auto_filter=f"A4:J{len(rows)}", merges=["A1:J1", "A2:J2"])
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=path.parent)
    os.close(descriptor)
    temporary = Path(temporary_name)
    try:
        with zipfile.ZipFile(temporary, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("[Content_Types].xml", _xlsx_content_types(1))
            archive.writestr("_rels/.rels", _xlsx_root_relationships())
            archive.writestr("xl/workbook.xml", _xlsx_workbook_xml(("Hardware",)))
            archive.writestr("xl/_rels/workbook.xml.rels", _xlsx_workbook_relationships(1))
            archive.writestr("xl/worksheets/sheet1.xml", sheet)
            archive.writestr("xl/styles.xml", _xlsx_styles())
            archive.writestr("xl/theme/theme1.xml", _XLSX_THEME_XML)
            archive.writestr("docProps/core.xml", _xlsx_core_properties("CNServerOps Hardware Inventory"))
            archive.writestr("docProps/app.xml", _xlsx_app_properties())
        _publish_validated_xlsx(
            temporary,
            path,
            expected_sheets=("Hardware",),
            required_values=tuple(
                dict.fromkeys(
                    [str(inventory.get("system_serial") or "UNKNOWN")]
                    + [
                        str(item.get("serial"))
                        for item in inventory.get("components", [])
                        if isinstance(item, Mapping)
                        and item.get("category") == "NIC/OCP"
                        and item.get("serial")
                    ]
                )
            ),
        )
    finally:
        if temporary.exists():
            temporary.unlink()
    return path


def _pdf_ascii(value: Any) -> str:
    text = _display(value, "")
    replacements = {"\u2013": "-", "\u2014": "-", "\u2011": "-", "\u2192": "->", "\u2022": "*"}
    for source, destination in replacements.items():
        text = text.replace(source, destination)
    return text.encode("ascii", "replace").decode("ascii")


def _pdf_escape(value: Any) -> str:
    return _pdf_ascii(value).replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def _pdf_cell_text(value: Any, width: float, *, size: float = 7.4) -> str:
    """Keep tabular presentation text inside its cell.

    The authoritative JSON/XLSX/raw evidence keeps the complete value.  The
    PDF is a compact presentation report, so long PCI/NIC model strings are
    deterministically shortened rather than drawn over adjacent columns.
    """
    text = _pdf_ascii(value)
    limit = max(8, int((width - 8) / (size * 0.52)))
    if len(text) <= limit:
        return text
    return text[: max(4, limit - 3)].rstrip() + "..."


class _PdfBuilder:
    width = 612
    height = 792

    def __init__(self, *, title: str) -> None:
        self.title = title
        self.pages: list[list[str]] = []
        self._commands: list[str] = []
        self._page_number = 0

    def new_page(self, *, subtitle: str = "") -> None:
        if self._commands:
            self._footer()
            self.pages.append(self._commands)
        self._commands = []
        self._page_number += 1
        self.rect(0, 742, 612, 50, fill=(0.09, 0.19, 0.33))
        self.text(36, 762, self.title, size=17, bold=True, color=(1, 1, 1))
        if subtitle:
            self.text(36, 746, subtitle, size=8, color=(0.82, 0.9, 0.95))

    def _footer(self) -> None:
        self.line(36, 28, 576, 28, color=(0.78, 0.83, 0.87))
        self.text(36, 16, "CNServerOps - credential-free operational report", size=7, color=(0.35, 0.4, 0.45))
        self.text(548, 16, str(self._page_number), size=7, color=(0.35, 0.4, 0.45))

    def text(
        self,
        x: float,
        y: float,
        value: Any,
        *,
        size: float = 10,
        bold: bool = False,
        color: tuple[float, float, float] = (0.08, 0.12, 0.16),
    ) -> None:
        font = "/F2" if bold else "/F1"
        self._commands.append(
            f"BT {color[0]:.3f} {color[1]:.3f} {color[2]:.3f} rg {font} {size:.1f} Tf {x:.1f} {y:.1f} Td ({_pdf_escape(value)}) Tj ET"
        )

    def rect(
        self,
        x: float,
        y: float,
        width: float,
        height: float,
        *,
        fill: tuple[float, float, float] | None = None,
        stroke: tuple[float, float, float] | None = None,
    ) -> None:
        if fill:
            self._commands.append(f"{fill[0]:.3f} {fill[1]:.3f} {fill[2]:.3f} rg {x:.1f} {y:.1f} {width:.1f} {height:.1f} re f")
        if stroke:
            self._commands.append(f"{stroke[0]:.3f} {stroke[1]:.3f} {stroke[2]:.3f} RG {x:.1f} {y:.1f} {width:.1f} {height:.1f} re S")

    def line(self, x1: float, y1: float, x2: float, y2: float, *, color: tuple[float, float, float]) -> None:
        self._commands.append(f"{color[0]:.3f} {color[1]:.3f} {color[2]:.3f} RG {x1:.1f} {y1:.1f} m {x2:.1f} {y2:.1f} l S")

    def wrapped_text(
        self,
        x: float,
        y: float,
        value: Any,
        *,
        width: float,
        size: float = 9,
        leading: float = 12,
        bold: bool = False,
        color: tuple[float, float, float] = (0.08, 0.12, 0.16),
        max_lines: int = 5,
    ) -> float:
        words = _pdf_ascii(value).split()
        limit = max(8, int(width / (size * 0.52)))
        lines: list[str] = []
        current = ""
        for word in words:
            candidate = f"{current} {word}".strip()
            if len(candidate) <= limit:
                current = candidate
            else:
                if current:
                    lines.append(current)
                current = word
        if current:
            lines.append(current)
        for line_value in lines[:max_lines]:
            self.text(x, y, line_value, size=size, bold=bold, color=color)
            y -= leading
        return y

    def section(self, y: float, title: str) -> float:
        self.rect(36, y - 4, 540, 22, fill=(0.91, 0.95, 0.97))
        self.text(44, y + 2, title.upper(), size=10, bold=True, color=(0.09, 0.28, 0.42))
        return y - 24

    def status_card(self, x: float, y: float, label: str, value: Any, *, width: float) -> None:
        normalized = _status(value)
        fill = (0.86, 0.95, 0.88) if normalized in _STATUS_PASS else (0.99, 0.92, 0.72) if normalized in _STATUS_REVIEW else (0.97, 0.82, 0.82) if normalized in _STATUS_FAIL else (0.9, 0.94, 0.97)
        self.rect(x, y, width, 44, fill=fill, stroke=(0.75, 0.8, 0.83))
        self.text(x + 10, y + 28, label.upper(), size=7, bold=True, color=(0.28, 0.33, 0.36))
        self.text(x + 10, y + 11, normalized, size=12, bold=True)

    def table(
        self,
        y: float,
        headers: Sequence[str],
        rows: Sequence[Sequence[Any]],
        widths: Sequence[float],
        *,
        row_height: float = 19,
    ) -> float:
        x0 = 36.0
        self.rect(x0, y - row_height + 4, sum(widths), row_height, fill=(0.08, 0.42, 0.53))
        x = x0
        for header, width in zip(headers, widths):
            self.text(x + 4, y - 8, header, size=7, bold=True, color=(1, 1, 1))
            x += width
        y -= row_height
        for row_index, row in enumerate(rows):
            fill = (0.97, 0.98, 0.99) if row_index % 2 else (1, 1, 1)
            self.rect(x0, y - row_height + 4, sum(widths), row_height, fill=fill)
            x = x0
            for value, width in zip(row, widths):
                self.text(x + 4, y - 8, _pdf_cell_text(value, width), size=7.4)
                x += width
            self.line(x0, y - row_height + 4, x0 + sum(widths), y - row_height + 4, color=(0.86, 0.89, 0.91))
            y -= row_height
        return y

    def save(self, path: Path) -> Path:
        if self._commands:
            self._footer()
            self.pages.append(self._commands)
            self._commands = []
        objects: list[bytes] = []

        def add(data: str | bytes) -> int:
            objects.append(data.encode("latin-1") if isinstance(data, str) else data)
            return len(objects)

        catalog_id = add("")
        pages_id = add("")
        font_regular = add("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
        font_bold = add("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>")
        page_ids: list[int] = []
        for page in self.pages:
            stream = ("\n".join(page) + "\n").encode("latin-1")
            content_id = add(b"<< /Length " + str(len(stream)).encode("ascii") + b" >>\nstream\n" + stream + b"endstream")
            page_id = add(
                f"<< /Type /Page /Parent {pages_id} 0 R /MediaBox [0 0 {self.width} {self.height}] "
                f"/Resources << /Font << /F1 {font_regular} 0 R /F2 {font_bold} 0 R >> >> /Contents {content_id} 0 R >>"
            )
            page_ids.append(page_id)
        objects[catalog_id - 1] = f"<< /Type /Catalog /Pages {pages_id} 0 R >>".encode("ascii")
        kids = " ".join(f"{item} 0 R" for item in page_ids)
        objects[pages_id - 1] = f"<< /Type /Pages /Kids [{kids}] /Count {len(page_ids)} >>".encode("ascii")
        data = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
        offsets = [0]
        for index, obj in enumerate(objects, start=1):
            offsets.append(len(data))
            data.extend(f"{index} 0 obj\n".encode("ascii"))
            data.extend(obj)
            data.extend(b"\nendobj\n")
        xref = len(data)
        data.extend(f"xref\n0 {len(objects) + 1}\n".encode("ascii"))
        data.extend(b"0000000000 65535 f \n")
        for offset in offsets[1:]:
            data.extend(f"{offset:010d} 00000 n \n".encode("ascii"))
        data.extend(
            f"trailer\n<< /Size {len(objects) + 1} /Root {catalog_id} 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode("ascii")
        )
        _atomic_bytes(path, bytes(data))
        return path


def _component_status_rows(result: Mapping[str, Any]) -> list[tuple[str, str]]:
    order = [
        ("Collection", "collection"),
        ("Serial Inventory", "serial_inventory"),
        ("CPU", "cpu"),
        ("Memory", "ram"),
        ("Storage", "storage"),
        ("Network", "nic"),
        ("PCIe", "pcie"),
        ("PSU", "psu"),
        ("Fans", "fans"),
        ("Sensors", "sensors"),
        ("SEL", "sel"),
        ("Firmware", "firmware_update"),
        ("Diagnostics", "system_diagnostics"),
        ("Central Sync", "central_link"),
    ]
    return [(label, _status(result.get(key), "NOT_TESTED")) for label, key in order]


def _firmware_rows(firmware: Mapping[str, Any]) -> list[list[str]]:
    components = firmware.get("components")
    if isinstance(components, list):
        rows = []
        for item in components:
            if not isinstance(item, Mapping):
                continue
            rows.append(
                [
                    _display(item.get("component")),
                    _display(item.get("before") or item.get("current")),
                    _display(item.get("target")),
                    _display(item.get("after")),
                    _status(item.get("result") or item.get("status"), "UNVERIFIED"),
                ]
            )
        if rows:
            return rows
    return [
        ["BIOS", _display((firmware.get("bios") or {}).get("value")), "-", "-", _status(firmware.get("bios_update"), "UNVERIFIED")],
        ["BMC", _display((firmware.get("bmc") or {}).get("value")), "-", "-", _status(firmware.get("bmc_update"), "UNVERIFIED")],
    ]


def write_production_pdf(
    path: Path,
    *,
    inventory: Mapping[str, Any],
    run: Mapping[str, Any],
    result: Mapping[str, Any],
    firmware: Mapping[str, Any],
    tests: Mapping[str, Any],
    finalization: Mapping[str, Any],
    central: Mapping[str, Any],
) -> Path:
    for payload in (inventory, run, result, firmware, tests, finalization, central):
        assert_no_sensitive_fields(payload)
    pdf = _PdfBuilder(title="CNServerOps Production Report")
    pdf.new_page(subtitle=f"RUN_ID {_display(run.get('run_id'))} | Runtime {_display(run.get('runtime_version'))}")
    pdf.text(36, 716, f"{_display(inventory.get('vendor'))} {_display(inventory.get('model'))}", size=18, bold=True)
    pdf.text(36, 696, f"System Serial: {_display(inventory.get('system_serial'))}", size=11)
    pdf.text(36, 680, f"Profile: {_display(run.get('test_profile') or run.get('workflow_mode'))}", size=9, color=(0.35, 0.4, 0.45))
    overall = _status(run.get("final_disposition") or result.get("overall"), "REVIEW")
    handoff = _status(result.get("handoff_status") or finalization.get("handoff_status"), "REVIEW_REQUIRED")
    pdf.status_card(36, 618, "Final Result", overall, width=170)
    readiness = _status(result.get("readiness") or ("READY_FOR_SALE" if overall == "PASS" else "REVIEW_REQUIRED"))
    pdf.status_card(224, 618, "Readiness", readiness, width=170)
    pdf.status_card(412, 618, "Handoff", handoff, width=164)

    y = pdf.section(588, "Firmware")
    firmware_rows = _firmware_rows(firmware)[:5]
    y = pdf.table(y, ["Component", "Before", "Target", "After", "Result"], firmware_rows, [92, 94, 94, 94, 166])
    y -= 10
    y = pdf.section(y, "Hardware and workflow status")
    statuses = _component_status_rows(result)
    paired: list[list[str]] = []
    for index in range(0, len(statuses), 2):
        left = statuses[index]
        right = statuses[index + 1] if index + 1 < len(statuses) else ("", "")
        paired.append([left[0], left[1], right[0], right[1]])
    y = pdf.table(y, ["Area", "Status", "Area", "Status"], paired, [110, 150, 110, 170])
    y -= 10
    y = pdf.section(y, "Errors and finalization")
    summary_rows = [
        ["New critical SEL", _display(result.get("new_critical_sel", 0))],
        ["Kernel hardware errors", _display(result.get("kernel_hw_errors", 0))],
        ["SEL cleanup", _status(finalization.get("sel_cleanup"), "NOT_PERFORMED")],
        ["SEL preserved", "YES" if result.get("sel_preserved") else "NO"],
        ["BMC soft reset", _status(finalization.get("bmc_soft_reset"), "UNVERIFIED")],
        ["Central artifacts", _status(central.get("artifact_status"), "PENDING_UPLOAD")],
    ]
    pdf.table(y, ["Check", "Result"], summary_rows, [245, 295])

    component_rows = serial_rows(inventory)
    per_page = 25
    for offset in range(0, max(1, len(component_rows)), per_page):
        pdf.new_page(subtitle="Normalized component inventory with provenance")
        y = pdf.section(712, "Serial and hardware inventory")
        page_rows = component_rows[offset : offset + per_page]
        if not page_rows:
            page_rows = [{"category": "-", "slot_location": "-", "model": "No components", "serial": "-", "health_status": "REVIEW"}]
        pdf.table(
            y,
            ["Category", "Slot", "Model / Part", "Serial", "Status"],
            [
                [row["category"], row["slot_location"], row["model"] or row["part_number"], row["serial"], row["health_status"]]
                for row in page_rows
            ],
            [80, 82, 180, 130, 68],
            row_height=21,
        )

    pdf.new_page(subtitle="Run, evidence, and capability details")
    y = pdf.section(712, "Identity and run binding")
    for label, value in (
        ("SERVER_ID", inventory.get("server_id")),
        ("RUN_ID", run.get("run_id")),
        ("RUNNER_ID", inventory.get("runner_id")),
        ("BOOT_ID", inventory.get("boot_id")),
        ("BMC auth", inventory.get("bmc_auth_state")),
        ("Primary MAC", inventory.get("primary_host_mac")),
    ):
        pdf.text(44, y, label, size=8, bold=True, color=(0.09, 0.28, 0.42))
        pdf.text(155, y, _display(value), size=8)
        y -= 18
    y -= 6
    y = pdf.section(y, "Evidence and interpretation")
    notes = [
        "Raw command output, hashes, manifests, and the authoritative run record remain separate from this presentation report.",
        "BMC authentication state is capability-specific and does not invalidate locally verified identity or hardware tests.",
        "Firmware update PASS requires post-update version verification. Unverified transports remain explicitly unavailable.",
    ]
    for note in notes:
        y = pdf.wrapped_text(44, y, f"- {note}", width=520, size=8.5, leading=13, max_lines=4) - 5
    return pdf.save(path)


def write_firmware_proof_pdf(
    path: Path,
    *,
    inventory: Mapping[str, Any],
    run: Mapping[str, Any],
    firmware: Mapping[str, Any],
) -> Path:
    for payload in (inventory, run, firmware):
        assert_no_sensitive_fields(payload)
    pdf = _PdfBuilder(title="CNServerOps Firmware Update Proof")
    pdf.new_page(subtitle=f"RUN_ID {_display(run.get('run_id'))}")
    pdf.text(36, 716, f"{_display(inventory.get('vendor'))} {_display(inventory.get('model'))}", size=17, bold=True)
    pdf.text(36, 694, f"Serial: {_display(inventory.get('system_serial'))}", size=11)
    y = pdf.section(656, "Before / target / after verification")
    rows = _firmware_rows(firmware)
    y = pdf.table(y, ["Component", "Before", "Target", "After", "Result"], rows, [90, 90, 90, 90, 180], row_height=23)
    y -= 14
    y = pdf.section(y, "Proof requirements")
    details = [
        ("Policy", firmware.get("policy") or "LATEST AVAILABLE"),
        ("Official source", firmware.get("official_source") or "NOT RECORDED"),
        ("Package", firmware.get("package") or "NOT DOWNLOADED"),
        ("Expected SHA256", firmware.get("expected_sha256") or "NOT AVAILABLE"),
        ("Actual SHA256", firmware.get("actual_sha256") or "NOT AVAILABLE"),
        ("Update started", firmware.get("update_started_at_utc") or "NOT PERFORMED"),
        ("Update completed", firmware.get("update_completed_at_utc") or "NOT PERFORMED"),
        ("Reboot", firmware.get("reboot_performed") if "reboot_performed" in firmware else "NOT PERFORMED"),
        ("Same SERVER_ID verified", firmware.get("same_server_id_verified") if "same_server_id_verified" in firmware else "NOT TESTED"),
    ]
    for label, value in details:
        pdf.text(44, y, label, size=8, bold=True, color=(0.09, 0.28, 0.42))
        y = pdf.wrapped_text(175, y, _display(value), width=390, size=8, leading=11, max_lines=3)
        y -= 9
    y -= 4
    pdf.rect(36, max(70, y - 64), 540, 58, fill=(0.99, 0.92, 0.72), stroke=(0.85, 0.71, 0.3))
    pdf.wrapped_text(
        48,
        max(94, y - 30),
        "Downloading or applying a package is not update proof. UPDATED_VERIFIED requires the post-update version to equal the locked target on the same physical SERVER_ID.",
        width=510,
        size=9,
        leading=13,
        bold=True,
        max_lines=4,
    )
    return pdf.save(path)


def write_extended_diagnostics_pdf(
    path: Path,
    *,
    inventory: Mapping[str, Any],
    run: Mapping[str, Any],
    result: Mapping[str, Any],
    diagnostics: Mapping[str, Any],
    finalization: Mapping[str, Any],
) -> Path:
    """Write a credential-free summary of the Option 2 diagnostic lifecycle."""
    for payload in (inventory, run, result, diagnostics, finalization):
        assert_no_sensitive_fields(payload)
    pdf = _PdfBuilder(title="CNServerOps Extended Diagnostics")
    pdf.new_page(subtitle=f"RUN_ID {_display(run.get('run_id'))} | Runtime {_display(run.get('runtime_version'))}")
    pdf.text(36, 716, f"{_display(inventory.get('vendor'))} {_display(inventory.get('model'))}", size=18, bold=True)
    pdf.text(36, 696, f"System Serial: {_display(inventory.get('system_serial'))}", size=11)
    pdf.status_card(36, 638, "Extended Diagnostics", diagnostics.get("status"), width=170)
    pdf.status_card(224, 638, "Final Disposition", run.get("final_disposition") or result.get("overall"), width=170)
    pdf.status_card(412, 638, "Readiness", result.get("readiness") or "NOT_REPORTED", width=164)
    y = pdf.section(606, "Capability and execution")
    rows = [
        ["Transport", diagnostics.get("transport", "")],
        ["Feature discovery", diagnostics.get("feature_catalog_endpoint", "")],
        ["Authentication", (diagnostics.get("authentication") or {}).get("status") or diagnostics.get("authentication_status", "")],
        ["Start", diagnostics.get("execution_started_at_utc") or diagnostics.get("discovery_started_at_utc", "")],
        ["End", diagnostics.get("execution_completed_at_utc") or diagnostics.get("discovery_completed_at_utc", "")],
        ["Duration (seconds)", diagnostics.get("duration_seconds", 0)],
        ["Reason", diagnostics.get("reason", "")],
    ]
    y = pdf.table(y, ["Field", "Value"], rows, [170, 370], row_height=22)
    y -= 12
    y = pdf.section(y, "Vendor artifact")
    artifact = diagnostics.get("artifact") if isinstance(diagnostics.get("artifact"), Mapping) else {}
    artifact_rows = [
        ["Filename", artifact.get("filename", "NOT_GENERATED")],
        ["SHA256", artifact.get("sha256", "NOT_GENERATED")],
        ["Bytes", artifact.get("size_bytes", "")],
        ["Format valid", artifact.get("zip_valid", "NOT_GENERATED")],
    ]
    y = pdf.table(y, ["Field", "Value"], artifact_rows, [170, 370], row_height=22)
    y -= 12
    y = pdf.section(y, "Findings and SEL lifecycle")
    findings = diagnostics.get("findings") or []
    summary_rows = [
        ["SEL before diagnostics", result.get("sel_entries", "")],
        ["SEL after diagnostics", (result.get("sel_after_extended_diagnostics") or {}).get("entry_count", "")],
        ["SEL cleanup", finalization.get("sel_cleanup", "")],
        ["Findings", "; ".join(str(item) for item in findings[:4]) or "NONE"],
        ["Final disposition", run.get("final_disposition") or result.get("overall")],
        ["Readiness", result.get("readiness") or "NOT_REPORTED"],
    ]
    pdf.table(y, ["Check", "Result"], summary_rows, [170, 370], row_height=24)
    return pdf.save(path)


def _html_status(value: Any) -> str:
    normalized = _status(value)
    css = "pass" if normalized in _STATUS_PASS else "fail" if normalized in _STATUS_FAIL else "review" if normalized in _STATUS_REVIEW else "info"
    return f'<span class="status {css}">{html.escape(normalized)}</span>'


def _html_table(headers: Sequence[str], rows: Iterable[Sequence[Any]]) -> str:
    head = "".join(f"<th>{html.escape(str(item))}</th>" for item in headers)
    body = "".join(
        "<tr>" + "".join(f"<td>{html.escape(_display(value))}</td>" for value in row) + "</tr>"
        for row in rows
    )
    return f"<div class=\"table-wrap\"><table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>"


def write_diagnostic_html(
    path: Path,
    *,
    inventory: Mapping[str, Any],
    run: Mapping[str, Any],
    result: Mapping[str, Any],
    firmware: Mapping[str, Any],
    tests: Mapping[str, Any],
    finalization: Mapping[str, Any],
    evidence_manifest: Mapping[str, Any],
) -> Path:
    for payload in (inventory, run, result, firmware, tests, finalization, evidence_manifest):
        assert_no_sensitive_fields(payload)
    sections = [
        "overview",
        "identity",
        "serials",
        "firmware",
        "hardware",
        "network",
        "sensors",
        "sel",
        "stress",
        "finalization",
        "evidence",
    ]
    nav = "".join(f'<a href="#{item}">{html.escape(item.title())}</a>' for item in sections)
    component_rows = serial_rows(inventory)
    nic_rows = physical_nic_rows(inventory)
    status_cards = "".join(
        f'<div class="card"><div class="label">{html.escape(label)}</div>{_html_status(value)}</div>'
        for label, value in _component_status_rows(result)
    )
    evidence_rows = []
    for item in evidence_manifest.get("artifacts", evidence_manifest.get("included", [])):
        if isinstance(item, Mapping):
            evidence_rows.append([item.get("name") or item.get("path") or item.get("arcname"), item.get("sha256"), item.get("size_bytes")])
    document = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>CNServerOps Diagnostic - {html.escape(_display(inventory.get('system_serial'), 'UNKNOWN'))}</title>
<style>
:root{{--navy:#183153;--teal:#147d92;--ink:#18232d;--muted:#63717d;--line:#d9e2e8;--bg:#f3f6f8;--pass:#18733b;--review:#9b6800;--fail:#b42318}}
*{{box-sizing:border-box}}body{{margin:0;font:14px/1.45 Arial,sans-serif;color:var(--ink);background:var(--bg)}}
header{{background:linear-gradient(120deg,var(--navy),#22597c);color:white;padding:28px 36px}}header h1{{margin:0 0 8px;font-size:28px}}header p{{margin:4px 0;color:#d9e8f2}}
nav{{position:sticky;top:0;z-index:2;background:white;border-bottom:1px solid var(--line);padding:10px 28px;display:flex;gap:8px;flex-wrap:wrap}}nav a{{color:var(--navy);text-decoration:none;padding:6px 9px;border-radius:5px}}nav a:hover{{background:#e7f1f5}}
main{{max-width:1240px;margin:22px auto;padding:0 22px}}section{{background:white;border:1px solid var(--line);border-radius:9px;margin:0 0 18px;padding:22px;box-shadow:0 2px 7px #1831530c}}h2{{margin:0 0 16px;color:var(--navy);font-size:20px}}h3{{color:var(--teal)}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:12px}}.card{{border:1px solid var(--line);border-radius:7px;padding:13px;background:#fbfcfd}}.label{{font-size:11px;text-transform:uppercase;color:var(--muted);font-weight:bold;margin-bottom:7px}}
.status{{font-weight:bold;border-radius:14px;padding:3px 9px;display:inline-block}}.status.pass{{background:#def3e5;color:var(--pass)}}.status.review{{background:#fff0c4;color:var(--review)}}.status.fail{{background:#fbe1df;color:var(--fail)}}.status.info{{background:#e5f0f6;color:#275775}}
.table-wrap{{overflow:auto}}table{{border-collapse:collapse;width:100%;min-width:680px}}th{{background:var(--teal);color:white;text-align:left;padding:9px;position:sticky;top:48px}}td{{padding:8px 9px;border-bottom:1px solid var(--line);vertical-align:top}}tbody tr:nth-child(even){{background:#f8fafb}}code{{background:#edf2f5;padding:2px 5px;border-radius:3px}}.notice{{border-left:4px solid var(--review);background:#fff8e2;padding:12px 14px}}
footer{{color:var(--muted);text-align:center;padding:24px}}@media print{{nav{{display:none}}body{{background:white}}section{{box-shadow:none;break-inside:avoid}}}}
</style></head><body>
<header><h1>CNServerOps Diagnostic</h1><p>{html.escape(_display(inventory.get('vendor')))} {html.escape(_display(inventory.get('model')))} | Serial {html.escape(_display(inventory.get('system_serial')))}</p><p>RUN_ID {html.escape(_display(run.get('run_id')))} | Generated {html.escape(_utc_now())}</p></header>
<nav>{nav}</nav><main>
<section id="overview"><h2>Overview</h2><div class="grid">{status_cards}</div><p class="notice">This viewer is a credential-free presentation derived from authoritative raw evidence. Unavailable capabilities remain explicit.</p></section>
<section id="identity"><h2>Identity</h2>{_html_table(['Identity','Value'], [['SERVER_ID',inventory.get('server_id')],['RUN_ID',run.get('run_id')],['RUNNER_ID',inventory.get('runner_id')],['BOOT_ID',inventory.get('boot_id')],['System Serial',inventory.get('system_serial')],['Primary Host MAC',inventory.get('primary_host_mac')],['BMC auth/capability',inventory.get('bmc_auth_state')]])}</section>
<section id="serials"><h2>Serial Inventory</h2>{_html_table(['Category','Slot / Location','Manufacturer','Model','Part Number','Serial','Firmware','Status','Source','Confidence'], [[row['category'],row['slot_location'],row['manufacturer'],row['model'],row['part_number'],row['serial'],row['firmware'],row['health_status'],row['source'],row['confidence']] for row in component_rows])}</section>
<section id="firmware"><h2>Firmware</h2>{_html_table(['Component','Before','Target','After','Result'], _firmware_rows(firmware))}</section>
<section id="hardware"><h2>Hardware</h2>{_html_table(['Area','Status'], _component_status_rows(result))}</section>
<section id="network"><h2>Network Adapters</h2>{_html_table(['Port','Interface','Adapter/Card Serial','MAC','PCI Address','Manufacturer','Adapter','Part Number','Link','Firmware','Source'], [[row[key] for key in ('port_label','interface','adapter_serial','mac','pci_address','manufacturer','adapter','part_number','link_state','firmware','source')] for row in nic_rows])}<p class="notice">NIC/card serials are component-level identity anchors. A trusted DMI/FRU system serial remains the server identity; NOT_EXPOSED is used when hardware does not expose a card serial.</p></section>
<section id="sensors"><h2>Sensors, Fans, and PSUs</h2><p>Sensor status: {_html_status(result.get('sensors'))} Fan status: {_html_status(result.get('fans'))} PSU status: {_html_status(result.get('psu'))}</p></section>
<section id="sel"><h2>System Event Log</h2>{_html_table(['Metric','Value'], [['Current entries',result.get('sel_entries')],['New critical entries',result.get('new_critical_sel',0)],['Cleanup',finalization.get('sel_cleanup')],['Preserved', 'YES' if result.get('sel_preserved') else 'NO']])}</section>
<section id="stress"><h2>Stress History</h2>{_html_table(['Field','Value'], [['Profile',run.get('test_profile')],['CPU',result.get('cpu')],['Memory',result.get('ram')],['Kernel HW errors',result.get('kernel_hw_errors',0)],['Evidence',tests.get('evidence_status','LOCAL_COMPLETE')]])}</section>
<section id="finalization"><h2>Finalization and Handoff</h2>{_html_table(['Action','Status'], [['SEL cleanup',finalization.get('sel_cleanup')],['BMC soft reset',finalization.get('bmc_soft_reset')],['Final sanity',finalization.get('final_sanity')],['Overall',result.get('overall')],['Readiness',result.get('readiness') or 'NOT_REPORTED'],['Handoff',result.get('handoff_status')]])}</section>
<section id="evidence"><h2>Evidence Manifest</h2>{_html_table(['Artifact','SHA256','Bytes'], evidence_rows)}<p>Raw JSON and command output remain in the run evidence directory and are not embedded as giant blobs in this viewer.</p></section>
</main><footer>CNServerOps vendor-neutral diagnostic report. No passwords, tokens, or private key material are reportable.</footer></body></html>"""
    _atomic_text(path, document)
    return path


def generate_human_reports(
    run_directory: Path,
    *,
    inventory: Mapping[str, Any],
    run: Mapping[str, Any],
    result: Mapping[str, Any],
    firmware: Mapping[str, Any],
    tests: Mapping[str, Any],
    finalization: Mapping[str, Any],
    central: Mapping[str, Any],
    evidence_manifest: Mapping[str, Any],
    fleet_intake: bool = False,
    extended_diagnostics: Mapping[str, Any] | None = None,
    report_variant: str = "",
) -> dict[str, Any]:
    """Generate all human-facing reports and a hashed manifest."""
    serial = _safe_token(inventory.get("system_serial"), "UNKNOWN_SERIAL")
    run_id = _safe_token(run.get("run_id"), "UNKNOWN_RUN")
    variant = _safe_token(report_variant, "") if str(report_variant or "").strip() else ""
    suffix = f"_{variant}" if variant else ""
    run_directory.mkdir(parents=True, exist_ok=True)
    paths = {
        "serials_xlsx": run_directory / f"CNServerOps_Serials_{serial}{suffix}.xlsx",
        "production_pdf": run_directory / (f"CNServerOps_Production_Report_{serial}{suffix}.pdf" if fleet_intake else f"CNServerOps_Production_Report_{serial}_{run_id}{suffix}.pdf"),
        "firmware_proof_pdf": run_directory / f"CNServerOps_Firmware_Update_Proof_{serial}_{run_id}{suffix}.pdf",
        "diagnostic_html": run_directory / f"CNServerOps_Diagnostic_{serial}_{run_id}{suffix}.html",
    }
    # Full Production, Fleet Intake, Firmware-only and Extended workflows all
    # need the same independently validated hardware-inventory workbook.
    # Keeping it unconditional prevents a successful Option 1 from losing the
    # customer's NIC/PCIe/storage evidence merely because it was not an intake
    # or extended-diagnostics run.
    paths["hardware_inventory_xlsx"] = run_directory / f"CNServerOps_Hardware_Inventory_{serial}{suffix}.xlsx"
    # Additional customer/order-style template export.  This is deliberately
    # additive: the authoritative Serial and Hardware workbooks above keep
    # their existing names/layouts and remain unchanged.
    paths["server_serial_template_xlsx"] = run_directory / f"CNServerOps_Server_Serials_{serial}{suffix}.xlsx"
    if extended_diagnostics is not None:
        paths["extended_diagnostics_pdf"] = run_directory / f"CNServerOps_Extended_Diagnostics_{serial}{suffix}.pdf"
    write_serial_workbook(paths["serials_xlsx"], inventory)
    write_hardware_workbook(paths["hardware_inventory_xlsx"], inventory)
    write_server_serial_template_workbook(paths["server_serial_template_xlsx"], inventory)
    write_production_pdf(
        paths["production_pdf"],
        inventory=inventory,
        run=run,
        result=result,
        firmware=firmware,
        tests=tests,
        finalization=finalization,
        central=central,
    )
    write_firmware_proof_pdf(paths["firmware_proof_pdf"], inventory=inventory, run=run, firmware=firmware)
    write_diagnostic_html(
        paths["diagnostic_html"],
        inventory=inventory,
        run=run,
        result=result,
        firmware=firmware,
        tests=tests,
        finalization=finalization,
        evidence_manifest=evidence_manifest,
    )
    if extended_diagnostics is not None:
        write_extended_diagnostics_pdf(
            paths["extended_diagnostics_pdf"],
            inventory=inventory,
            run=run,
            result=result,
            diagnostics=extended_diagnostics,
            finalization=finalization,
        )
    artifacts: list[dict[str, Any]] = []
    for key, path in paths.items():
        artifact: dict[str, Any] = {
            "type": key.upper(),
            "name": path.name,
            "path": str(path),
            "sha256": _sha256(path),
            "size_bytes": path.stat().st_size,
            "state": "LOCAL_COMPLETE",
        }
        if path.suffix.lower() == ".xlsx":
            expected_sheets = (
                ("Serials", "Server Access")
                if key == "serials_xlsx"
                else ("Server SNs",)
                if key == "server_serial_template_xlsx"
                else ("Hardware",)
            )
            artifact["validation"] = validate_xlsx(
                path,
                expected_sheets=expected_sheets,
                required_values=(str(inventory.get("system_serial") or "UNKNOWN"),),
            )
        artifacts.append(artifact)
    manifest = {
        "schema_version": 1,
        "generated_at_utc": _utc_now(),
        "variant": variant or "PRIMARY",
        "run_id": run.get("run_id"),
        "server_id": inventory.get("server_id"),
        "system_serial": inventory.get("system_serial"),
        "sensitive_data_excluded": True,
        "artifacts": artifacts,
    }
    assert_no_sensitive_fields(manifest)
    manifest_name = "human-report-manifest.json" if not variant else f"human-report-manifest_{variant}.json"
    _atomic_text(run_directory / manifest_name, json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    return manifest


def _atomic_text(path: Path, value: str) -> None:
    _atomic_bytes(path, value.encode("utf-8"))


def _atomic_bytes(path: Path, value: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
        Path(temporary_name).replace(path)
    finally:
        temporary = Path(temporary_name)
        if temporary.exists():
            temporary.unlink()
