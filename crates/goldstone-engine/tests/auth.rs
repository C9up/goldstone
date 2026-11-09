//! Authenticity checks, offline: every DNS record a check needs is put in
//! the cache by hand, so the verdicts come from records the test controls.

use goldstone_engine::auth::{
    authenticate, dkim_key_record, dmarc_record, not_found_record, spf_record, AuthOptions,
    Envelope, Outcome, TxtCache, Verdict,
};
use mail_auth::common::crypto::Ed25519Key;
use mail_auth::common::headers::HeaderWriter;
use mail_auth::dkim::generate::DkimKeyPair;
use mail_auth::dkim::DkimSigner;
use mail_auth::hickory_resolver::config::{NameServerConfig, ResolverConfig, ResolverOpts};
use mail_auth::MessageAuthenticator;
use std::time::Duration;

const DAY: Duration = Duration::from_secs(86_400);

/// A resolver that can answer nothing: every name a test did not put in the
/// cache fails to resolve, as it would with DNS down.
fn no_dns() -> MessageAuthenticator {
    // Nothing listens on 127.0.0.1:53 (resolvers that run locally use
    // 127.0.0.53): every query times out.
    let config = ResolverConfig::from_name_servers(vec![NameServerConfig::udp(
        "127.0.0.1".parse().unwrap(),
    )]);
    let mut options = ResolverOpts::default();
    options.timeout = Duration::from_millis(200);
    options.attempts = 1;
    MessageAuthenticator::new(config, options).unwrap()
}

struct Domain {
    key: DkimKeyPair,
}

impl Domain {
    fn new() -> Self {
        Self {
            key: DkimKeyPair::generate_ed25519().unwrap(),
        }
    }

    /// Publish this domain's key, SPF and DMARC records in the cache.
    fn publish(&self, cache: &TxtCache, domain: &str, dmarc: &str) {
        cache.insert_record(
            &format!("s1._domainkey.{domain}."),
            dkim_key_record(&format!(
                "v=DKIM1; k=ed25519; p={}",
                self.key.encoded_public_key()
            )),
            DAY,
        );
        cache.insert_record(
            &format!("{domain}."),
            spf_record("v=spf1 ip4:203.0.113.7 -all"),
            DAY,
        );
        cache.insert_record(&format!("_dmarc.{domain}."), dmarc_record(dmarc), DAY);
        // DMARC walks up the tree: the parent has no record.
        cache.insert_record("_dmarc.test.", not_found_record(), DAY);
    }

    fn sign(&self, domain: &str, message: &str) -> String {
        let key = Ed25519Key::from_pkcs8_der(self.key.private_key()).unwrap();
        let signature = DkimSigner::from_key(key)
            .domain(domain)
            .selector("s1")
            .headers(["From", "To", "Subject"])
            .sign(message.as_bytes())
            .unwrap();
        format!("{}{message}", signature.to_header())
    }
}

fn message(from: &str) -> String {
    format!("From: {from}\r\nTo: alice@example.test\r\nSubject: hello\r\n\r\nThe body.\r\n")
}

#[tokio::test]
async fn a_message_signed_by_its_from_domain_passes() {
    let cache = TxtCache::new(64);
    let bank = Domain::new();
    bank.publish(&cache, "bank.test", "v=DMARC1; p=reject");
    let raw = bank.sign("bank.test", &message("ceo@bank.test"));

    let verdict = authenticate(raw.as_bytes(), &AuthOptions::default(), &no_dns(), &cache)
        .await
        .unwrap();
    assert_eq!(verdict.dkim.len(), 1);
    assert_eq!(verdict.dkim[0].result, Outcome::Pass);
    assert_eq!(verdict.dkim[0].domain.as_deref(), Some("bank.test"));
    assert_eq!(verdict.dkim[0].selector.as_deref(), Some("s1"));
    assert_eq!(verdict.dmarc, Outcome::Pass);
    assert_eq!(verdict.dmarc_policy, "reject");
    assert_eq!(verdict.summary, Outcome::Pass);
    assert_eq!(verdict.spf, Outcome::None, "no envelope was given");
}

#[tokio::test]
async fn a_body_changed_after_signing_fails_dkim_and_dmarc() {
    let cache = TxtCache::new(64);
    let bank = Domain::new();
    bank.publish(&cache, "bank.test", "v=DMARC1; p=reject");
    let raw = bank
        .sign("bank.test", &message("ceo@bank.test"))
        .replace("The body.", "Wire 10 000 to us.");

    let verdict = authenticate(raw.as_bytes(), &AuthOptions::default(), &no_dns(), &cache)
        .await
        .unwrap();
    assert_ne!(verdict.dkim[0].result, Outcome::Pass);
    assert_eq!(verdict.summary, Outcome::Fail);
}

#[tokio::test]
async fn a_spoofed_from_signed_by_another_domain_fails() {
    // The attacker signs properly — with their own domain. The From says the
    // bank, whose DMARC policy is reject: DKIM passes, DMARC does not.
    let cache = TxtCache::new(64);
    Domain::new().publish(&cache, "bank.test", "v=DMARC1; p=reject");
    let attacker = Domain::new();
    attacker.publish(&cache, "attacker.test", "v=DMARC1; p=none");
    let raw = attacker.sign("attacker.test", &message("ceo@bank.test"));

    let verdict = authenticate(raw.as_bytes(), &AuthOptions::default(), &no_dns(), &cache)
        .await
        .unwrap();
    assert_eq!(verdict.dkim[0].result, Outcome::Pass);
    assert_eq!(verdict.dkim[0].domain.as_deref(), Some("attacker.test"));
    assert_eq!(verdict.dmarc_domain.as_deref(), Some("bank.test"));
    assert_eq!(verdict.dmarc, Outcome::Fail);
    assert_eq!(verdict.summary, Outcome::Fail);
}

#[tokio::test]
async fn spf_follows_the_envelope_it_is_given() {
    let cache = TxtCache::new(64);
    let shop = Domain::new();
    shop.publish(&cache, "shop.test", "v=DMARC1; p=quarantine");
    let unsigned = message("orders@shop.test");
    let envelope = |ip: &str| AuthOptions {
        envelope: Envelope {
            ip: Some(ip.parse().unwrap()),
            helo: Some("mx.shop.test".into()),
            mail_from: Some("bounces@shop.test".into()),
        },
        ..AuthOptions::default()
    };

    let listed = authenticate(
        unsigned.as_bytes(),
        &envelope("203.0.113.7"),
        &no_dns(),
        &cache,
    )
    .await
    .unwrap();
    assert_eq!(listed.spf, Outcome::Pass);
    assert_eq!(
        listed.dmarc,
        Outcome::Pass,
        "SPF aligned with the From domain"
    );

    let elsewhere = authenticate(
        unsigned.as_bytes(),
        &envelope("198.51.100.9"),
        &no_dns(),
        &cache,
    )
    .await
    .unwrap();
    assert_eq!(elsewhere.spf, Outcome::Fail);
    assert_eq!(elsewhere.summary, Outcome::Fail);
}

#[tokio::test]
async fn dns_that_cannot_answer_is_never_a_pass() {
    // Signed, but the key cannot be fetched: nothing in the cache, no DNS.
    let raw = Domain::new().sign("bank.test", &message("ceo@bank.test"));
    let verdict = authenticate(
        raw.as_bytes(),
        &AuthOptions::default(),
        &no_dns(),
        &TxtCache::new(64),
    )
    .await
    .unwrap();
    assert_eq!(verdict.dkim[0].result, Outcome::TempError);
    assert_ne!(verdict.summary, Outcome::Pass);
    assert_eq!(verdict.summary, Outcome::TempError);
}

#[tokio::test]
async fn the_deadline_turns_a_slow_check_into_temperror() {
    let raw = Domain::new().sign("bank.test", &message("ceo@bank.test"));
    let options = AuthOptions {
        timeout: Duration::from_millis(1),
        ..AuthOptions::default()
    };
    let verdict = authenticate(raw.as_bytes(), &options, &no_dns(), &TxtCache::new(64))
        .await
        .unwrap();
    assert_eq!(verdict.summary, Outcome::TempError);
}

#[tokio::test]
async fn only_so_many_signatures_are_checked() {
    let cache = TxtCache::new(64);
    let bank = Domain::new();
    bank.publish(&cache, "bank.test", "v=DMARC1; p=reject");
    let mut raw = message("ceo@bank.test");
    for _ in 0..12 {
        raw = bank.sign("bank.test", &raw);
    }
    let verdict = authenticate(raw.as_bytes(), &AuthOptions::default(), &no_dns(), &cache)
        .await
        .unwrap();
    assert_eq!(verdict.dkim.len(), 5);
}

#[tokio::test]
async fn an_oversized_or_empty_message_is_refused() {
    let cache = TxtCache::new(4);
    let small = AuthOptions {
        max_bytes: 10,
        ..AuthOptions::default()
    };
    assert!(authenticate(&[b'x'; 11], &small, &no_dns(), &cache)
        .await
        .is_err());
    assert!(
        authenticate(b"", &AuthOptions::default(), &no_dns(), &cache)
            .await
            .is_err()
    );
}

#[test]
fn the_cache_keeps_records_until_their_ttl_and_stays_bounded() {
    use mail_auth::ResolverCache;
    let cache = TxtCache::new(2);
    cache.insert_record("a.", spf_record("v=spf1 -all"), DAY);
    cache.insert_record("expired.", spf_record("v=spf1 -all"), Duration::ZERO);
    assert!(cache.get("a.").is_some());
    assert!(cache.get("expired.").is_none());
    // Full: the expired entry makes room.
    cache.insert_record("b.", spf_record("v=spf1 -all"), DAY);
    assert!(cache.get("a.").is_some() && cache.get("b.").is_some());
}

/// What the application is shown, next to what was checked.
async fn shown_and_checked(raw: &str, cache: &TxtCache) -> (Vec<Option<String>>, Verdict) {
    let shown = goldstone_engine::parse(raw.as_bytes(), &goldstone_engine::Limits::default())
        .map(|m| m.from.into_iter().map(|f| f.address).collect())
        .unwrap_or_default();
    let verdict = authenticate(raw.as_bytes(), &AuthOptions::default(), &no_dns(), cache)
        .await
        .unwrap();
    (shown, verdict)
}

fn attacker_and_bank(cache: &TxtCache) -> Domain {
    Domain::new().publish(cache, "bank.test", "v=DMARC1; p=reject");
    let attacker = Domain::new();
    attacker.publish(cache, "evil.test", "v=DMARC1; p=none");
    attacker
}

#[tokio::test]
async fn a_colon_less_line_cannot_split_the_from_shown_from_the_from_checked() {
    // mail-auth's own header scanner ended the header block at "X"; the
    // parser the application reads went on to a second From.
    let cache = TxtCache::new(64);
    let attacker = attacker_and_bank(&cache);
    let raw = attacker.sign(
        "evil.test",
        "From: a@evil.test\r\nTo: v@x.test\r\nSubject: hi\r\nX\r\nFrom: ceo@bank.test\r\n\r\nbody\r\n",
    );
    let (shown, verdict) = shown_and_checked(&raw, &cache).await;
    assert_ne!(
        verdict.summary,
        Outcome::Pass,
        "shown {shown:?}: {verdict:?}"
    );
    assert!(
        !shown.contains(&Some("ceo@bank.test".into())) || verdict.summary != Outcome::Pass,
        "the bank address must never come with a pass"
    );
}

#[tokio::test]
async fn a_pass_only_ever_covers_the_from_the_application_is_shown() {
    // Header blocks two parsers are known to read differently. The attacker
    // signs each with its own key; whatever the verdict, a pass must be for
    // the domain the application shows.
    let cache = TxtCache::new(64);
    let attacker = attacker_and_bank(&cache);
    let corpus = [
        "From: a@evil.test\r\nTo: v@x.test\r\nSubject: hi\r\nX\r\nFrom: ceo@bank.test\r\n\r\nbody\r\n",
        "From: a@evil.test\nTo: v@x.test\nSubject: hi\nX\nFrom: ceo@bank.test\n\nbody\n",
        "From: a@evil.test\r\nTo: v@x.test\r\nSubject: hi\r\n \r\nFrom: ceo@bank.test\r\n\r\nbody\r\n",
        "From: a@evil.test\r\nTo: v@x.test\r\nSubject: hi\r\n\r\rFrom: ceo@bank.test\r\n\r\nbody\r\n",
        "From: a@evil.test\r\nTo: v@x.test\r\nSubject: hi\r\nFrom : ceo@bank.test\r\n\r\nbody\r\n",
        "From: a@evil.test\r\nTo: v@x.test\r\nSubject: hi\r\nFrom\t: ceo@bank.test\r\n\r\nbody\r\n",
        "From: a@evil.test\r\nTo: v@x.test\r\nSubject: hi\r\nFr\0om: ceo@bank.test\r\n\r\nbody\r\n",
        "From: a@evil.test\r\nTo: v@x.test\r\nSubject: hi\r\nFrom: Bank: ceo@bank.test;\r\n\r\nbody\r\n",
        "From: a@evil.test\r\nTo: v@x.test\r\nSubject: hi\r\nFrom: <@evil.test:ceo@bank.test>\r\n\r\nbody\r\n",
        "From: ceo@bank.test\r\nX\r\nFrom: a@evil.test\r\nTo: v@x.test\r\nSubject: hi\r\n\r\nbody\r\n",
        "From: ceo@bank.test, a@evil.test\r\nTo: v@x.test\r\nSubject: hi\r\n\r\nbody\r\n",
        "From: a@evil.test\r\nTo: v@x.test\r\nSubject: hi\r\n\r\nbody\r\n",
    ];
    for message in corpus {
        let raw = attacker.sign("evil.test", message);
        let (shown, verdict) = shown_and_checked(&raw, &cache).await;
        if verdict.summary == Outcome::Pass {
            assert_eq!(shown, [Some("a@evil.test".to_owned())], "for {message:?}");
            assert_eq!(
                verdict.from_domain.as_deref(),
                Some("evil.test"),
                "for {message:?}"
            );
        }
        assert!(
            !shown.contains(&Some("ceo@bank.test".into())) || verdict.summary != Outcome::Pass,
            "{message:?} showed the bank with a pass"
        );
    }
}

#[tokio::test]
async fn a_display_name_is_not_what_passes() {
    // The name says the bank; the address, the one DMARC checks, does not.
    let cache = TxtCache::new(64);
    let attacker = attacker_and_bank(&cache);
    let raw = attacker.sign("evil.test", &message("\"ceo@bank.test\" <a@evil.test>"));
    let verdict = authenticate(raw.as_bytes(), &AuthOptions::default(), &no_dns(), &cache)
        .await
        .unwrap();
    assert_eq!(verdict.summary, Outcome::Pass);
    assert_eq!(verdict.from_domain.as_deref(), Some("evil.test"));
    assert_eq!(verdict.dmarc_domain.as_deref(), Some("evil.test"));
}

#[tokio::test]
async fn a_from_header_added_after_signing_is_never_a_pass() {
    // The bank signed one From; a second one, same domain, was prepended
    // and DMARC alone still passes on it.
    let cache = TxtCache::new(64);
    let bank = Domain::new();
    bank.publish(&cache, "bank.test", "v=DMARC1; p=reject");
    let signed = bank.sign(
        "bank.test",
        "From: newsletter@bank.test\r\nTo: v@x.test\r\nSubject: news\r\n\r\nbody\r\n",
    );
    let replay = format!(
        "From: \"Bank Security\" <security@bank.test>\r\nSubject: Urgent: reset your password\r\n{signed}"
    );
    let verdict = authenticate(
        replay.as_bytes(),
        &AuthOptions::default(),
        &no_dns(),
        &cache,
    )
    .await
    .unwrap();
    assert_ne!(verdict.summary, Outcome::Pass, "{verdict:?}");
    assert_eq!(verdict.summary, Outcome::Fail);
    assert_eq!(verdict.from_domain, None);
}

#[tokio::test]
async fn a_duplicated_subject_is_never_a_pass_either() {
    let cache = TxtCache::new(64);
    let bank = Domain::new();
    bank.publish(&cache, "bank.test", "v=DMARC1; p=reject");
    let signed = bank.sign("bank.test", &message("newsletter@bank.test"));
    let replay = format!("Subject: Urgent: reset your password\r\n{signed}");
    let verdict = authenticate(
        replay.as_bytes(),
        &AuthOptions::default(),
        &no_dns(),
        &cache,
    )
    .await
    .unwrap();
    assert_eq!(verdict.dmarc, Outcome::Pass, "DMARC alone does not see it");
    assert_eq!(verdict.summary, Outcome::Fail);
}

#[tokio::test]
async fn the_from_domain_a_pass_covers_is_reported() {
    let cache = TxtCache::new(64);
    let bank = Domain::new();
    bank.publish(&cache, "bank.test", "v=DMARC1; p=reject");
    let raw = bank.sign("bank.test", &message("CEO <Ceo@Bank.TEST>"));
    let verdict = authenticate(raw.as_bytes(), &AuthOptions::default(), &no_dns(), &cache)
        .await
        .unwrap();
    assert_eq!(verdict.summary, Outcome::Pass);
    assert_eq!(verdict.from_domain.as_deref(), Some("bank.test"));
}
