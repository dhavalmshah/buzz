//! Exercise uploads and parsed message dispatch through only the loopback HTTP boundary.
use std::io::{Cursor, Write};
use std::sync::{Arc, Mutex};

use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{HeaderMap, StatusCode, Uri};
use axum::routing::{post, put};
use axum::{Json, Router};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use nostr::{Event, JsonUtil, Keys};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use zip::write::SimpleFileOptions;

const CHANNEL: &str = "123e4567-e89b-12d3-a456-426614174000";
const CONTENT_TYPES: &[u8] = br#"<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>"#;
const RELS: &[u8] = br#"<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>"#;
const DOCUMENT: &[u8] = br#"<?xml version="1.0"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>Original document</w:t></w:r></w:p></w:body></w:document>"#;

fn package(parts: &[(&str, &[u8])]) -> Vec<u8> {
    package_with_method(parts, zip::CompressionMethod::Deflated)
}

fn package_with_method(parts: &[(&str, &[u8])], method: zip::CompressionMethod) -> Vec<u8> {
    let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
    for (name, bytes) in parts {
        zip.start_file(
            *name,
            SimpleFileOptions::default().compression_method(method),
        )
        .unwrap();
        zip.write_all(bytes).unwrap();
    }
    zip.finish().unwrap().into_inner()
}

fn word_package() -> Vec<u8> {
    // A perfectly ordinary entry order that infer identifies only as ZIP.
    package(&[
        ("custom.xml", b"<custom/>"),
        ("[Content_Types].xml", CONTENT_TYPES),
        ("_rels/.rels", RELS),
        ("word/document.xml", DOCUMENT),
    ])
}

fn hash(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[derive(Clone, Debug)]
struct Request {
    path: String,
    headers: HeaderMap,
    body: Vec<u8>,
}

#[derive(Default)]
struct Fixture {
    requests: Mutex<Vec<Request>>,
    status: Option<StatusCode>,
    tamper: Option<&'static str>,
}

async fn relay(fixture: Arc<Fixture>) -> (String, tokio::task::JoinHandle<()>) {
    async fn upload(
        State(fixture): State<Arc<Fixture>>,
        uri: Uri,
        headers: HeaderMap,
        body: Bytes,
    ) -> (StatusCode, Json<Value>) {
        let sniffed = infer::get(&body)
            .map(|v| v.mime_type())
            .unwrap_or("application/octet-stream");
        let mut descriptor = json!({"url": format!("http://downloads.invalid/{}", hash(&body)), "sha256": hash(&body), "size": body.len(), "type": sniffed, "uploaded": 0});
        if let Some(field) = fixture.tamper {
            descriptor[field] = match field {
                "size" => json!(body.len() + 1),
                "sha256" => json!("0".repeat(64)),
                _ => json!("image/jpeg"),
            };
        }
        let status = if uri.path() == "/upload" {
            fixture.status.unwrap_or(StatusCode::OK)
        } else {
            StatusCode::OK
        };
        fixture.requests.lock().unwrap().push(Request {
            path: uri.path().into(),
            headers,
            body: body.to_vec(),
        });
        (status, Json(descriptor))
    }
    async fn event(
        State(fixture): State<Arc<Fixture>>,
        headers: HeaderMap,
        body: Bytes,
    ) -> Json<Value> {
        fixture.requests.lock().unwrap().push(Request {
            path: "/events".into(),
            headers,
            body: body.to_vec(),
        });
        Json(json!({"event_id": "fake", "accepted": true}))
    }
    let router = Router::new()
        .route("/upload", put(upload))
        .route("/media/upload", put(upload))
        .route("/events", post(event))
        .route("/query", post(|| async { Json(json!([])) }))
        .layer(DefaultBodyLimit::max(12 * 1024 * 1024))
        .with_state(fixture);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    (url, task)
}

async fn cli(url: &str, keys: &Keys, command: &[String]) -> i32 {
    let mut args = vec![
        "buzz".into(),
        "--relay".into(),
        url.into(),
        "--private-key".into(),
        keys.secret_key().to_secret_hex(),
        "--auth-tag".into(),
        buzz_sdk::nip_oa::compute_auth_tag(&Keys::generate(), &keys.public_key(), "").unwrap(),
    ];
    args.extend_from_slice(command);
    buzz_cli::run_from_args(args).await
}

fn send(content: &str, files: &[std::path::PathBuf], exact: bool) -> Vec<String> {
    let mut args = vec![
        "messages".into(),
        "send".into(),
        "--channel".into(),
        CHANNEL.into(),
        "--content".into(),
        content.into(),
    ];
    if exact {
        args.push("--exact-content".into());
    }
    for file in files {
        args.extend(["--file".into(), file.to_str().unwrap().into()]);
    }
    args
}

fn expected_mime(original: &[u8]) -> &'static str {
    if original.starts_with(b"%PDF-") {
        "application/pdf"
    } else if original.starts_with(b"PK") {
        "application/zip"
    } else if original.starts_with(&[0xff, 0xd8, 0xff]) {
        "image/jpeg"
    } else if original.get(4..8) == Some(b"ftyp") {
        "video/mp4"
    } else {
        "application/octet-stream"
    }
}

fn assert_upload(request: &Request, original: &[u8], keys: &Keys) {
    assert_eq!(request.path, "/upload");
    assert_eq!(request.body, original);
    assert_eq!(request.headers["x-sha-256"], hash(original));
    let mime = expected_mime(original);
    assert_eq!(request.headers["content-type"], mime);
    let owner_tag = request.headers["x-auth-tag"].to_str().unwrap();
    buzz_sdk::nip_oa::verify_auth_tag(owner_tag, &keys.public_key()).unwrap();
    let token = request.headers["authorization"]
        .to_str()
        .unwrap()
        .strip_prefix("Nostr ")
        .unwrap();
    let auth = Event::from_json(URL_SAFE_NO_PAD.decode(token).unwrap()).unwrap();
    auth.verify().unwrap();
    assert_eq!(auth.pubkey, keys.public_key());
    assert_eq!(auth.kind.as_u16(), 24242);
    assert!(auth
        .tags
        .iter()
        .any(|t| t.as_slice() == ["x", &hash(original)]));
    assert!(auth.tags.iter().any(|t| t.as_slice() == ["t", "upload"]));
    assert!(auth
        .tags
        .iter()
        .any(|t| t.as_slice() == ["server", request.headers["host"].to_str().unwrap()]));
}

fn assert_event(request: &Request, content: &str, originals: &[Vec<u8>], keys: &Keys) {
    let event = Event::from_json(&request.body).unwrap();
    event.verify().unwrap();
    assert_eq!(event.pubkey, keys.public_key());
    assert_eq!(event.content.as_bytes(), content.as_bytes());
    let tags: Vec<_> = event
        .tags
        .iter()
        .filter(|t| t.as_slice()[0] == "imeta")
        .collect();
    assert_eq!(tags.len(), originals.len());
    for (tag, original) in tags.iter().zip(originals) {
        let mime = expected_mime(original);
        assert_eq!(
            tag.as_slice(),
            [
                "imeta".into(),
                format!("url http://downloads.invalid/{}", hash(original)),
                format!("m {mime}"),
                format!("x {}", hash(original)),
                format!("size {}", original.len())
            ]
        );
    }
}

#[tokio::test]
async fn parsed_exact_content_keeps_signed_envelope_and_ordered_original_imeta() {
    let dir = tempfile::tempdir().unwrap();
    let originals = vec![
        "Original UTF-8\nहेलो\t\n".as_bytes().to_vec(),
        b"%PDF-1.7\noriginal PDF bytes\n%%EOF\n".to_vec(),
        word_package(),
    ];
    let paths: Vec<_> = ["original.txt", "original.pdf", "original.docx"]
        .iter()
        .zip(&originals)
        .map(|(name, bytes)| {
            let path = dir.path().join(name);
            std::fs::write(&path, bytes).unwrap();
            path
        })
        .collect();
    assert_eq!(
        infer::get(&originals[2]).unwrap().mime_type(),
        "application/zip"
    );
    let fixture = Arc::new(Fixture::default());
    let (url, task) = relay(fixture.clone()).await;
    let keys = Keys::generate();
    let content = "{\"signedEnvelope\":\"verbatim\"}\n\n";
    assert_eq!(cli(&url, &keys, &send(content, &paths, true)).await, 0);
    let requests = fixture.requests.lock().unwrap();
    assert_eq!(requests.len(), 4);
    for (request, original) in requests.iter().zip(&originals) {
        assert_upload(request, original, &keys);
    }
    assert_event(&requests[3], content, &originals, &keys);
    task.abort();
}

#[tokio::test]
async fn default_content_keeps_media_markdown_and_uses_document_file_links() {
    let dir = tempfile::tempdir().unwrap();
    let originals = vec![
        vec![
            0xff, 0xd8, 0xff, 0xe0, 0, 0x10, b'J', b'F', b'I', b'F', 0, 1,
        ],
        b"original text".to_vec(),
        b"\0\0\0\x18ftypmp42\0\0\0\0".to_vec(),
    ];
    let paths: Vec<_> = ["media.jpg", "original.txt", "media.mp4"]
        .iter()
        .zip(&originals)
        .map(|(name, bytes)| {
            let path = dir.path().join(name);
            std::fs::write(&path, bytes).unwrap();
            path
        })
        .collect();
    let fixture = Arc::new(Fixture::default());
    let (url, task) = relay(fixture.clone()).await;
    let keys = Keys::generate();
    let expected = format!(
        "hello\n![image](http://downloads.invalid/{})\n[file](http://downloads.invalid/{})\n![video](http://downloads.invalid/{})",
        hash(&originals[0]),
        hash(&originals[1]),
        hash(&originals[2])
    );
    assert_eq!(cli(&url, &keys, &send("hello", &paths, false)).await, 0);
    let requests = fixture.requests.lock().unwrap();
    assert_event(&requests[3], &expected, &originals, &keys);
    task.abort();
}

#[tokio::test]
async fn documents_never_use_legacy_upload_and_bad_descriptors_never_publish() {
    let dir = tempfile::tempdir().unwrap();
    for (name, original) in [
        ("original.txt", b"original text".to_vec()),
        ("original.pdf", b"%PDF-1.7\noriginal".to_vec()),
        ("original.docx", word_package()),
    ] {
        let path = dir.path().join(name);
        std::fs::write(&path, original).unwrap();
        for (status, tamper) in [
            (Some(StatusCode::NOT_FOUND), None),
            (Some(StatusCode::METHOD_NOT_ALLOWED), None),
            (None, Some("sha256")),
            (None, Some("size")),
            (None, Some("type")),
        ] {
            let fixture = Arc::new(Fixture {
                status,
                tamper,
                ..Default::default()
            });
            let (url, task) = relay(fixture.clone()).await;
            assert_ne!(
                cli(
                    &url,
                    &Keys::generate(),
                    &send("envelope", std::slice::from_ref(&path), true)
                )
                .await,
                0
            );
            let requests = fixture.requests.lock().unwrap();
            assert_eq!(
                requests.len(),
                1,
                "document failure must not fall back or publish"
            );
            assert_eq!(requests[0].path, "/upload");
            task.abort();
        }
    }
}

#[tokio::test]
async fn document_boundaries_and_disguised_binary_are_enforced_on_upload_path() {
    let dir = tempfile::tempdir().unwrap();
    let fixture = Arc::new(Fixture::default());
    let (url, task) = relay(fixture.clone()).await;
    let keys = Keys::generate();
    let mut oversize_pdf = vec![b' '; 10 * 1024 * 1024 + 1];
    oversize_pdf[..5].copy_from_slice(b"%PDF-");
    let cases = vec![
        ("valid.txt", vec![b'x'; 10 * 1024 * 1024], true),
        ("large.txt", vec![b'x'; 10 * 1024 * 1024 + 1], false),
        ("large.pdf", oversize_pdf, false),
        ("empty.txt", vec![], false),
        ("control.txt", b"hello\0world".to_vec(), false),
        ("utf8.txt", vec![0xff, 0xff], false),
        ("executable.txt", b"MZ\x90\0binary".to_vec(), false),
        ("binary.txt", b"\x7fELF\x02\x01\x01\0".to_vec(), false),
        ("text.bin", b"ordinary text".to_vec(), false),
        (
            "archive.docx",
            package(&[("other.txt", b"not Word")]),
            false,
        ),
        (
            "missing.docx",
            package(&[
                ("[Content_Types].xml", CONTENT_TYPES),
                ("_rels/.rels", RELS),
                ("word/other.xml", DOCUMENT),
            ]),
            false,
        ),
        (
            "unsafe.docx",
            package(&[
                ("[Content_Types].xml", CONTENT_TYPES),
                ("_rels/.rels", RELS),
                ("word/document.xml", DOCUMENT),
                ("../escape", b"bad"),
            ]),
            false,
        ),
        ("word.zip", word_package(), false),
    ];
    let mut accepted = 0;
    for (name, original, valid) in cases {
        let path = dir.path().join(name);
        std::fs::write(&path, original).unwrap();
        let code = cli(
            &url,
            &keys,
            &[
                "upload".into(),
                "file".into(),
                "--file".into(),
                path.to_str().unwrap().into(),
            ],
        )
        .await;
        assert_eq!(code == 0, valid, "{name}");
        if valid {
            accepted += 1;
        }
        assert_eq!(
            fixture.requests.lock().unwrap().len(),
            accepted,
            "{name} must refuse before HTTP"
        );
    }
    task.abort();
}

#[tokio::test]
async fn final_composed_content_limit_is_checked_before_publication() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("original.txt");
    std::fs::write(&path, b"original").unwrap();
    let fixture = Arc::new(Fixture::default());
    let (url, task) = relay(fixture.clone()).await;
    assert_ne!(
        cli(
            &url,
            &Keys::generate(),
            &send(&"x".repeat(65536), &[path], false)
        )
        .await,
        0
    );
    assert!(fixture
        .requests
        .lock()
        .unwrap()
        .iter()
        .all(|r| r.path != "/events"));
    task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn compiled_command_preserves_stdin_newlines_and_original_attachment() {
    use std::process::{Command, Stdio};
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("original.txt");
    let original = b"original bytes\n".to_vec();
    std::fs::write(&path, &original).unwrap();
    let fixture = Arc::new(Fixture::default());
    let (url, task) = relay(fixture.clone()).await;
    let keys = Keys::generate();
    let key = keys.secret_key().to_secret_hex();
    let owner_tag =
        buzz_sdk::nip_oa::compute_auth_tag(&Keys::generate(), &keys.public_key(), "").unwrap();
    let content = "{\"envelope\":\"`literal` $data\"}\n\n";
    let output = tokio::task::spawn_blocking(move || {
        let mut process = Command::new(env!("CARGO_BIN_EXE_buzz"))
            .env_clear()
            .env("BUZZ_PRIVATE_KEY", key)
            .env("BUZZ_AUTH_TAG", owner_tag)
            .args([
                "--relay",
                &url,
                "messages",
                "send",
                "--channel",
                CHANNEL,
                "--content",
                "-",
                "--exact-content",
                "--file",
                path.to_str().unwrap(),
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        process
            .stdin
            .take()
            .unwrap()
            .write_all(content.as_bytes())
            .unwrap();
        process.wait_with_output().unwrap()
    })
    .await
    .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let requests = fixture.requests.lock().unwrap();
    assert_eq!(requests.len(), 2);
    assert_upload(&requests[0], &original, &keys);
    assert_event(&requests[1], content, &[original], &keys);
    task.abort();
}

#[tokio::test]
async fn media_still_uses_legacy_endpoint_on_404_and_405() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("media.jpg");
    std::fs::write(
        &path,
        [
            0xff, 0xd8, 0xff, 0xe0, 0, 0x10, b'J', b'F', b'I', b'F', 0, 1,
        ],
    )
    .unwrap();
    for status in [StatusCode::NOT_FOUND, StatusCode::METHOD_NOT_ALLOWED] {
        let fixture = Arc::new(Fixture {
            status: Some(status),
            ..Default::default()
        });
        let (url, task) = relay(fixture.clone()).await;
        assert_eq!(
            cli(
                &url,
                &Keys::generate(),
                &send("hello", std::slice::from_ref(&path), false)
            )
            .await,
            0
        );
        let requests = fixture.requests.lock().unwrap();
        assert_eq!(
            requests.iter().map(|r| r.path.as_str()).collect::<Vec<_>>(),
            ["/upload", "/media/upload", "/events"]
        );
        task.abort();
    }
}

fn patch_central(bytes: &mut [u8], name: &str, offset: usize, value: &[u8]) {
    let start = bytes
        .windows(4)
        .enumerate()
        .find_map(|(i, w)| {
            (w == b"PK\x01\x02" && bytes.get(i + 46..i + 46 + name.len()) == Some(name.as_bytes()))
                .then_some(i)
        })
        .unwrap();
    bytes[start + offset..start + offset + value.len()].copy_from_slice(value);
}

#[tokio::test]
async fn word_packages_bound_entries_metadata_and_declared_sizes_and_reject_duplicates() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("original.docx");
    let fixture = Arc::new(Fixture::default());
    let (url, task) = relay(fixture.clone()).await;
    let keys = Keys::generate();
    let mut oversized_metadata = word_package();
    patch_central(
        &mut oversized_metadata,
        "_rels/.rels",
        24,
        &(256 * 1024 + 1u32).to_le_bytes(),
    );
    let mut oversized_total = word_package();
    patch_central(
        &mut oversized_total,
        "custom.xml",
        24,
        &(10 * 1024 * 1024 + 1u32).to_le_bytes(),
    );
    let mut encrypted = word_package();
    patch_central(&mut encrypted, "word/document.xml", 8, &1u16.to_le_bytes());
    let mut duplicate = package(&[
        ("[Content_Types].xml", CONTENT_TYPES),
        ("_rels/.rels", RELS),
        ("word/document.xml", DOCUMENT),
        ("_rels/.relx", RELS),
    ]);
    for start in (0..duplicate.len().saturating_sub(11))
        .filter(|i| duplicate[*i..].starts_with(b"_rels/.relx"))
        .collect::<Vec<_>>()
    {
        duplicate[start..start + 11].copy_from_slice(b"_rels/.rels");
    }
    let mut ambiguous = word_package();
    let footer = ambiguous[ambiguous.len() - 22..].to_vec();
    ambiguous.extend_from_slice(&footer);
    let mut zip64 = word_package();
    let mut footer = zip64.split_off(zip64.len() - 22);
    let record_offset = zip64.len() as u64;
    let directory_size = u32::from_le_bytes(footer[12..16].try_into().unwrap()) as u64;
    let directory_offset = u32::from_le_bytes(footer[16..20].try_into().unwrap()) as u64;
    let mut record = vec![0u8; 56];
    record[..4].copy_from_slice(b"PK\x06\x06");
    record[4..12].copy_from_slice(&44u64.to_le_bytes());
    record[24..32].copy_from_slice(&4u64.to_le_bytes());
    record[32..40].copy_from_slice(&4u64.to_le_bytes());
    record[40..48].copy_from_slice(&directory_size.to_le_bytes());
    record[48..56].copy_from_slice(&directory_offset.to_le_bytes());
    zip64.extend_from_slice(&record);
    let mut locator = vec![0u8; 20];
    locator[..4].copy_from_slice(b"PK\x06\x07");
    locator[8..16].copy_from_slice(&record_offset.to_le_bytes());
    locator[16..20].copy_from_slice(&1u32.to_le_bytes());
    zip64.extend_from_slice(&locator);
    footer[10..12].copy_from_slice(&u16::MAX.to_le_bytes());
    zip64.extend_from_slice(&footer);
    let names: Vec<_> = (0..257).map(|i| format!("part{i}.xml")).collect();
    let parts: Vec<_> = names
        .iter()
        .map(|n| (n.as_str(), b"<part/>".as_slice()))
        .collect();
    for original in [
        oversized_metadata,
        oversized_total,
        encrypted,
        duplicate,
        ambiguous,
        zip64,
        package(&parts),
    ] {
        std::fs::write(&path, original).unwrap();
        assert_ne!(
            cli(
                &url,
                &keys,
                &[
                    "upload".into(),
                    "file".into(),
                    "--file".into(),
                    path.to_str().unwrap().into()
                ]
            )
            .await,
            0
        );
        assert!(fixture.requests.lock().unwrap().is_empty());
    }
    // infer's canonical DOCX detection remains supported alongside generic ZIP order.
    let canonical = package(&[
        ("word/document.xml", DOCUMENT),
        ("[Content_Types].xml", CONTENT_TYPES),
        ("_rels/.rels", RELS),
    ]);
    assert_eq!(
        infer::get(&canonical).unwrap().mime_type(),
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    );
    std::fs::write(&path, canonical).unwrap();
    assert_eq!(
        cli(
            &url,
            &keys,
            &[
                "upload".into(),
                "file".into(),
                "--file".into(),
                path.to_str().unwrap().into()
            ]
        )
        .await,
        0
    );
    task.abort();
}

#[tokio::test]
async fn word_with_stored_embedded_zip_and_footer_bytes_uploads_original_verbatim() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("embedded.docx");
    let embedded = package_with_method(
        &[("sheet.xml", b"<sheet/>")],
        zip::CompressionMethod::Stored,
    );
    let content_types = String::from_utf8(CONTENT_TYPES.to_vec()).unwrap().replace(
        "</Types>",
        r#"<Default Extension="zip" ContentType="application/zip"/><Default Extension="bin" ContentType="application/octet-stream"/></Types>"#,
    );
    let original = package_with_method(
        &[
            ("custom.xml", b"<custom/>"),
            ("[Content_Types].xml", content_types.as_bytes()),
            ("_rels/.rels", RELS),
            ("word/document.xml", DOCUMENT),
            ("word/embeddings/source.zip", &embedded),
            (
                "word/media/binary.bin",
                b"embedded binary PK\x06\x06 and PK\x06\x07 footer signatures",
            ),
        ],
        zip::CompressionMethod::Stored,
    );
    assert_eq!(
        original.windows(4).filter(|v| *v == b"PK\x05\x06").count(),
        2
    );
    std::fs::write(&path, &original).unwrap();
    let fixture = Arc::new(Fixture::default());
    let (url, task) = relay(fixture.clone()).await;
    let keys = Keys::generate();
    assert_eq!(
        cli(&url, &keys, &send("envelope\n", &[path], true)).await,
        0
    );
    let requests = fixture.requests.lock().unwrap();
    assert_eq!(requests.len(), 2);
    assert_upload(&requests[0], &original, &keys);
    assert_event(&requests[1], "envelope\n", &[original], &keys);
    task.abort();
}
