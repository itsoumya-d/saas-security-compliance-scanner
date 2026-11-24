from src.saas_sec.models import FindingSeverity
from src.saas_sec.scanner import SecurityComplianceScanner


def test_crypto_key_rotation_and_weak_ciphers():
    scanner = SecurityComplianceScanner()
    # Insecure algorithm + expired key
    findings = scanner.audit_crypto_key_rotation(key_id="kms-key-legacy", age_days=120, algorithm="3DES")
    assert len(findings) == 2
    assert any(f.finding_id == "CRYPTO-001" and f.severity == FindingSeverity.CRITICAL for f in findings)
    assert any(f.finding_id == "CRYPTO-002" and f.severity == FindingSeverity.HIGH for f in findings)

    # Valid key
    valid_findings = scanner.audit_crypto_key_rotation(key_id="kms-key-prod", age_days=45, algorithm="AES-256-GCM")
    assert len(valid_findings) == 0


def test_api_security_headers_audit():
    scanner = SecurityComplianceScanner()
    insecure_headers = {
        "Content-Type": "application/json",
        "Access-Control-Allow-Origin": "*",
    }
    findings = scanner.audit_api_security_headers("/api/v1/customer-events", insecure_headers)
    assert len(findings) >= 2
    ids = [f.finding_id for f in findings]
    assert "HDR-001" in ids
    assert "HDR-002" in ids
    assert "CORS-001" in ids


def test_cloud_storage_bucket_audit():
    scanner = SecurityComplianceScanner()
    # Public unencrypted bucket
    findings = scanner.audit_cloud_storage_bucket("customer-pii-backup", is_public=True, encryption_enabled=False, versioning_enabled=False)
    assert len(findings) == 2
    assert any(f.finding_id == "CLOUD-001" and f.severity == FindingSeverity.CRITICAL for f in findings)
    assert any(f.finding_id == "CLOUD-002" and f.severity == FindingSeverity.HIGH for f in findings)

    # Compliant secure bucket
    secure_findings = scanner.audit_cloud_storage_bucket("secure-vault", is_public=False, encryption_enabled=True, versioning_enabled=True)
    assert len(secure_findings) == 0


def test_audit_report_generation():
    scanner = SecurityComplianceScanner()
    clean_findings = scanner.audit_crypto_key_rotation(key_id="kms-1", age_days=30, algorithm="AES-256")
    report = scanner.generate_report(clean_findings, total_scanned=5)
    assert report.passed is True
    assert report.critical_count == 0
