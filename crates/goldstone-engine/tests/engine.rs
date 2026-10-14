use goldstone_engine::{parse, safe_file_name, Limits, ParseError};

const HEAD: &str = "From: Bob <bob@example.test>\r\nTo: alice@example.test\r\nSubject: =?utf-8?Q?Facture_n=C2=B0_42?=\r\nDate: Tue, 13 Oct 2026 21:00:00 +0200\r\nMessage-ID: <m1@example.test>\r\nMIME-Version: 1.0\r\n";

fn multipart(boundary: &str, parts: &[String]) -> String {
    let mut out = format!("Content-Type: multipart/mixed; boundary={boundary}\r\n\r\n");
    for part in parts {
        out.push_str(&format!("--{boundary}\r\n{part}\r\n"));
    }
    out.push_str(&format!("--{boundary}--\r\n"));
    out
}

fn attachment(name: &str, base64: &str) -> String {
    format!("Content-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=\"{name}\"\r\nContent-Transfer-Encoding: base64\r\n\r\n{base64}")
}

#[test]
fn an_ordinary_message_comes_out_whole() {
    let raw = format!(
        "{HEAD}{}",
        multipart(
            "B",
            &[
                "Content-Type: text/plain; charset=utf-8\r\n\r\nHello Alice".into(),
                attachment("invoice.pdf", "JVBERi0="),
            ]
        )
    );
    let m = parse(raw.as_bytes(), &Limits::default()).unwrap();
    assert_eq!(m.subject.as_deref(), Some("Facture n° 42"));
    assert_eq!(m.from[0].address.as_deref(), Some("bob@example.test"));
    assert_eq!(m.from[0].name.as_deref(), Some("Bob"));
    assert_eq!(m.to[0].address.as_deref(), Some("alice@example.test"));
    assert_eq!(m.message_id.as_deref(), Some("m1@example.test"));
    assert_eq!(m.date.as_deref(), Some("2026-10-13T21:00:00+02:00"));
    assert_eq!(m.text.as_deref(), Some("Hello Alice"));
    assert_eq!(m.attachments.len(), 1);
    assert_eq!(m.attachments[0].file_name, "invoice.pdf");
    assert_eq!(m.attachments[0].content, b"%PDF-");
    assert!(m.headers.iter().any(|(n, _)| n == "Message-ID"));
}

#[test]
fn html_is_sanitized_and_the_received_html_kept_apart() {
    let hostile = r#"<p onclick="alert(1)">hi</p><script>alert(2)</script><img src=x onerror=alert(3)><a href="javascript:alert(4)">x</a><svg onload=alert(5)></svg>"#;
    let raw = format!("{HEAD}Content-Type: text/html\r\n\r\n{hostile}\r\n");
    let m = parse(raw.as_bytes(), &Limits::default()).unwrap();
    let html = m.html.unwrap();
    for banned in [
        "<script",
        "onclick",
        "onerror",
        "onload",
        "javascript:",
        "<svg",
    ] {
        assert!(!html.contains(banned), "{banned} survived: {html}");
    }
    assert!(html.contains("<p>hi</p>"), "{html}");
    assert!(m.unsanitized_html.unwrap().contains("<script>"));
}

#[test]
fn a_text_only_message_has_no_html_made_up_for_it() {
    let raw = format!("{HEAD}Content-Type: text/plain\r\n\r\nplain\r\n");
    let m = parse(raw.as_bytes(), &Limits::default()).unwrap();
    assert_eq!(m.html, None);
    assert_eq!(m.unsanitized_html, None);
}

#[test]
fn an_oversized_message_is_refused_before_it_is_read() {
    let limits = Limits {
        max_bytes: 100,
        ..Limits::default()
    };
    // Not even a message: refused on size, not on content.
    assert_eq!(
        parse(&[0xff; 101], &limits).unwrap_err(),
        ParseError::TooLarge {
            size: 101,
            max: 100
        }
    );
}

fn nested(levels: usize) -> String {
    let mut body = String::from("leaf\r\n");
    for i in 0..levels {
        body = format!(
            "Content-Type: multipart/mixed; boundary=b{i}\r\n\r\n--b{i}\r\n{body}\r\n--b{i}--\r\n"
        );
    }
    format!("{HEAD}{body}")
}

#[test]
fn deep_nesting_is_refused() {
    // 40 levels: few parts, so it is the depth that refuses.
    assert_eq!(
        parse(nested(40).as_bytes(), &Limits::default()).unwrap_err(),
        ParseError::TooDeep { depth: 40, max: 32 }
    );
    // 5 000 levels: refused (the part count trips first), and quickly.
    assert!(parse(nested(5_000).as_bytes(), &Limits::default()).is_err());
}

#[test]
fn too_many_parts_are_refused() {
    let parts: Vec<String> = (0..100_000)
        .map(|_| "Content-Type: text/plain\r\n\r\nx".into())
        .collect();
    let raw = format!("{HEAD}{}", multipart("P", &parts));
    assert!(matches!(
        parse(raw.as_bytes(), &Limits::default()),
        Err(ParseError::TooManyParts { max: 1_000, .. })
    ));
}

#[test]
fn too_many_attachments_are_refused() {
    let parts: Vec<String> = (0..101)
        .map(|i| attachment(&format!("f{i}.bin"), "eA=="))
        .collect();
    let raw = format!("{HEAD}{}", multipart("A", &parts));
    assert_eq!(
        parse(raw.as_bytes(), &Limits::default()).unwrap_err(),
        ParseError::TooManyAttachments {
            count: 101,
            max: 100
        }
    );
}

#[test]
fn an_oversized_attachment_is_refused() {
    let limits = Limits {
        max_attachment_bytes: 4,
        ..Limits::default()
    };
    let raw = format!(
        "{HEAD}{}",
        multipart("A", &[attachment("big.bin", "AAAAAAAA")])
    );
    assert_eq!(
        parse(raw.as_bytes(), &limits).unwrap_err(),
        ParseError::AttachmentTooLarge { size: 6, max: 4 }
    );
}

#[test]
fn attachment_names_cannot_leave_their_directory() {
    let cases = [
        (Some("../../etc/passwd"), "passwd"),
        (Some("..\\..\\windows\\win.ini"), "win.ini"),
        (Some("/etc/shadow"), "shadow"),
        (Some("a\0.exe"), "a.exe"),
        (Some("evil\r\nX-Injected: 1"), "evilX-Injected: 1"),
        (Some(".."), "attachment-3"),
        (Some(".htaccess"), "htaccess"),
        (Some("con.txt"), "_con.txt"),
        (Some("NUL"), "_NUL"),
        (Some("   "), "attachment-3"),
        (Some("report.pdf.   "), "report.pdf"),
        (None, "attachment-3"),
    ];
    for (name, expected) in cases {
        assert_eq!(safe_file_name(name, 2), expected, "for {name:?}");
    }
    let long = "é".repeat(300);
    let safe = safe_file_name(Some(&long), 0);
    assert!(safe.len() <= 255 && safe.chars().all(|c| c == 'é'));
}

#[test]
fn names_from_a_real_message_are_cleaned_too() {
    let raw = format!(
        "{HEAD}{}",
        multipart(
            "N",
            &[
                attachment("../../boot.ini", "eA=="),
                "Content-Type: application/octet-stream\r\nContent-Disposition: attachment; filename*=utf-8''%2e%2e%2f%2e%2e%2fpwn\r\n\r\nx".into(),
            ]
        )
    );
    let m = parse(raw.as_bytes(), &Limits::default()).unwrap();
    let names: Vec<_> = m.attachments.iter().map(|a| a.file_name.as_str()).collect();
    assert_eq!(names, ["boot.ini", "pwn"]);
    assert_eq!(
        m.attachments[0].original_name.as_deref(),
        Some("../../boot.ini")
    );
}

#[test]
fn malformed_input_is_answered_never_crashed_on() {
    let mut random = Vec::with_capacity(5 * 1024 * 1024);
    let mut state: u64 = 68;
    for _ in 0..random.capacity() {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        random.push((state >> 56) as u8);
    }
    let inputs: Vec<(&str, Vec<u8>)> = vec![
        ("random bytes", random),
        ("unclosed boundary", format!("{HEAD}Content-Type: multipart/mixed; boundary=Z\r\n\r\n--Z\r\nContent-Type: text/plain\r\n\r\nstart{}", "x".repeat(100_000)).into_bytes()),
        ("bad base64", format!("{HEAD}Content-Type: text/plain\r\nContent-Transfer-Encoding: base64\r\n\r\n!!!!$$$$%%%%\r\n====\r\n").into_bytes()),
        ("bad encodings", b"From: =?x-unknown?Q?=FF=FE?= <a@x.test>\r\nSubject: =?utf-8?B?!!!?=\r\nContent-Type: text/plain; charset=x-klingon\r\n\r\n\xff\xfe\x00body\r\n".to_vec()),
        ("huge header", format!("{HEAD}X-Big: {}\r\n\r\nbody\r\n", "A".repeat(20 * 1024 * 1024)).into_bytes()),
    ];
    for (label, raw) in inputs {
        // Any answer is fine — a message or a refusal — as long as there is one.
        let _ = std::panic::catch_unwind(|| parse(&raw, &Limits::default()))
            .unwrap_or_else(|_| panic!("{label} panicked"));
    }
    assert_eq!(
        parse(b"", &Limits::default()).unwrap_err(),
        ParseError::NotAMessage
    );
}
