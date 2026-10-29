//! Narrow document carrier classification; this does not sanitize document contents.
use std::io::Cursor;
use std::path::Path;

use crate::client::BlobDescriptor;
use crate::error::CliError;

pub(crate) const MAX_DOCUMENT_BYTES: u64 = 10 * 1024 * 1024;
const DOCX: &str = "application/vnd.openxmlformats-officedocument.wordprocessingml.document";
const ZIP: &str = "application/zip";
const PARTS: [&str; 3] = ["[Content_Types].xml", "_rels/.rels", "word/document.xml"];

#[derive(Clone, Copy)]
pub(crate) enum Document {
    Pdf,
    Text,
    Word,
}

fn invalid_docx() -> CliError {
    CliError::Usage("invalid or unsupported DOCX package".into())
}

/// Recognize only the supported originals, preserving the byte-sniffed transport MIME.
pub(crate) fn classify(path: &str, bytes: &[u8], mime: &str) -> Result<Option<Document>, CliError> {
    let extension = Path::new(path)
        .extension()
        .and_then(|s| s.to_str())
        .unwrap_or("");
    let document = if mime == "application/pdf" {
        Some(Document::Pdf)
    } else if mime == DOCX || (mime == ZIP && extension.eq_ignore_ascii_case("docx")) {
        validate_word_package(bytes)?;
        Some(Document::Word)
    } else if mime == "application/octet-stream" && extension.eq_ignore_ascii_case("txt") {
        let text = std::str::from_utf8(bytes)
            .map_err(|_| CliError::Usage("TXT must contain nonempty UTF-8 text".into()))?;
        if text.is_empty()
            || text
                .chars()
                .any(|c| c.is_control() && !matches!(c, '\n' | '\r' | '\t'))
        {
            return Err(CliError::Usage(
                "TXT contains empty or unsafe control data".into(),
            ));
        }
        Some(Document::Text)
    } else {
        None
    };
    if document.is_some() && bytes.len() as u64 > MAX_DOCUMENT_BYTES {
        return Err(CliError::Usage("document exceeds 10 MiB".into()));
    }
    Ok(document)
}

fn validate_word_package(bytes: &[u8]) -> Result<(), CliError> {
    if bytes.len() as u64 > MAX_DOCUMENT_BYTES {
        return Err(invalid_docx());
    }
    // Bound the parser's entry allocation before opening the archive. This narrow
    // carrier accepts single-disk, non-ZIP64 packages, sufficient for <=10 MiB DOCX.
    // The parser may otherwise fall back to an older footer or prefer ZIP64,
    // bypassing the allocation bound. Reject ambiguous footer layouts up front.
    let mut ends = bytes
        .windows(4)
        .enumerate()
        .filter(|(_, w)| *w == b"PK\x05\x06");
    let end = ends.next().map(|(i, _)| i).ok_or_else(invalid_docx)?;
    if ends.next().is_some()
        || bytes
            .windows(4)
            .any(|w| matches!(w, b"PK\x06\x06" | b"PK\x06\x07"))
    {
        return Err(invalid_docx());
    }
    let eocd = bytes
        .get(end..)
        .filter(|v| v.len() >= 22)
        .ok_or_else(invalid_docx)?;
    let u16_at = |i| u16::from_le_bytes([eocd[i], eocd[i + 1]]) as usize;
    let entries = u16_at(10);
    if eocd.len() != 22 + u16_at(20)
        || u16_at(4) != 0
        || u16_at(6) != 0
        || u16_at(8) != entries
        || !(3..=256).contains(&entries)
    {
        return Err(invalid_docx());
    }
    let mut archive = zip::ZipArchive::new(Cursor::new(bytes)).map_err(|_| invalid_docx())?;
    // zip indexes names uniquely; a reduced count exposes duplicate directory names.
    if archive.len() != entries || archive.offset() != 0 {
        return Err(invalid_docx());
    }
    let mut found = [false; 3];
    let mut total = 0u64;
    for i in 0..archive.len() {
        let file = archive.by_index_raw(i).map_err(|_| invalid_docx())?;
        let name = file.name();
        if file.enclosed_name().is_none()
            || name.contains('\\')
            || name.contains(':')
            || name.split('/').any(|part| matches!(part, "." | ".."))
            || file.is_symlink()
        {
            return Err(invalid_docx());
        }
        total = total.checked_add(file.size()).ok_or_else(invalid_docx)?;
        if total > MAX_DOCUMENT_BYTES {
            return Err(invalid_docx());
        }
        if let Some(index) = PARTS.iter().position(|part| *part == name) {
            // Metadata is bounded independently. No member is extracted or XML resolved.
            let limit = if index == 2 {
                MAX_DOCUMENT_BYTES
            } else {
                256 * 1024
            };
            if file.encrypted() || file.size() == 0 || file.size() > limit {
                return Err(invalid_docx());
            }
            found[index] = true;
        }
    }
    if found.iter().all(|v| *v) {
        Ok(())
    } else {
        Err(invalid_docx())
    }
}

impl Document {
    pub(crate) fn validate_descriptor(
        self,
        desc: &BlobDescriptor,
        hash: &str,
        size: usize,
    ) -> Result<(), CliError> {
        let mime_matches = match self {
            Self::Pdf => desc.mime_type == "application/pdf",
            Self::Text => desc.mime_type == "application/octet-stream",
            Self::Word => matches!(desc.mime_type.as_str(), DOCX | ZIP),
        };
        if desc.sha256 != hash || desc.size != size as u64 || !mime_matches {
            return Err(CliError::Other(
                "upload descriptor does not match original document bytes".into(),
            ));
        }
        Ok(())
    }
}
