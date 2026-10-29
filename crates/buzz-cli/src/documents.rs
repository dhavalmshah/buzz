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
    let (entries, directory) = word_footer(bytes)?;
    // Fixed offset prevents the parser treating an embedded archive as prepended ZIP.
    let config = zip::read::Config {
        archive_offset: zip::read::ArchiveOffset::Known(0),
    };
    let mut archive =
        zip::ZipArchive::with_config(config, Cursor::new(bytes)).map_err(|_| invalid_docx())?;
    // zip indexes names uniquely; a reduced count exposes duplicate directory names.
    if archive.len() != entries
        || archive.offset() != 0
        || archive.central_directory_start() != directory as u64
    {
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

// zip 8.6 has no entry-allocation limit and may retry older EOCD records.
// Bound every footer it can use at Known(0), not byte patterns inside members.
fn word_footer(bytes: &[u8]) -> Result<(usize, usize), CliError> {
    let mut root = None;
    for (position, magic) in bytes.windows(4).enumerate() {
        if magic != b"PK\x05\x06" {
            continue;
        }
        let Some(header) = bytes.get(position..position + 22) else {
            continue;
        };
        let u16_at = |i| u16::from_le_bytes([header[i], header[i + 1]]) as usize;
        let u32_at = |i| {
            u32::from_le_bytes([header[i], header[i + 1], header[i + 2], header[i + 3]]) as usize
        };
        let end = position + 22 + u16_at(20);
        if end > bytes.len() {
            continue;
        }
        let (on_disk, entries, size, directory) = (u16_at(8), u16_at(10), u32_at(12), u32_at(16));
        if entries == u16::MAX as usize
            || size == u32::MAX as usize
            || directory == u32::MAX as usize
        {
            // ZIP64 is considered only for sentinel EOCD fields and an adjacent
            // locator whose fixed-offset target actually contains an EOCD64.
            if let Some(locator) = position
                .checked_sub(20)
                .and_then(|i| bytes.get(i..position))
            {
                if locator.starts_with(b"PK\x06\x07") {
                    let offset =
                        u64::from_le_bytes(locator[8..16].try_into().map_err(|_| invalid_docx())?);
                    if let Ok(offset) = usize::try_from(offset) {
                        if offset < position - 20
                            && bytes.get(offset..offset.saturating_add(4)) == Some(b"PK\x06\x06")
                        {
                            return Err(invalid_docx());
                        }
                    }
                }
            }
        }
        let fixed_directory = directory < position
            && bytes.get(directory..directory.saturating_add(4)) == Some(b"PK\x01\x02");
        // The parser accepts zero-total EOCD before checking its directory offset.
        if (fixed_directory || entries == 0) && on_disk > 256 {
            return Err(invalid_docx());
        }
        if end == bytes.len() && fixed_directory {
            if root.is_some()
                || u16_at(4) != 0
                || u16_at(6) != 0
                || on_disk != entries
                || !(3..=256).contains(&entries)
                || directory.checked_add(size) != Some(position)
            {
                return Err(invalid_docx());
            }
            root = Some((entries, directory));
        }
    }
    root.ok_or_else(invalid_docx)
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
