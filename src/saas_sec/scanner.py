from .models import AuditReport, FindingSeverity, SecurityFinding


class SecurityComplianceScanner:
    """Automated security posture, cryptographic, and SOC 2 / ISO 27001 compliance scanner."""

    MAX_KEY_AGE_DAYS = 90
    INSECURE_ALGORITHMS = {"des", "3des", "rc4", "md5", "sha1"}

    def audit_crypto_key_rotation(
        self, key_id: str, age_days: int, algorithm: str
    ) -> list[SecurityFinding]:
        """Audit cryptographic key age and encryption algorithm strength."""
        findings = []
        algo_norm = algorithm.lower().strip()

        if algo_norm in self.INSECURE_ALGORITHMS:
            findings.append(
                SecurityFinding(
                    finding_id="CRYPTO-001",
                    category="Cryptography",
                    severity=FindingSeverity.CRITICAL,
                    title="Deprecate Weak Cryptographic Algorithm",
                    description=f"Key {key_id} utilizes deprecated/insecure algorithm '{algorithm}'.",
                    remediation="Migrate key to AES-256-GCM, RSA-4096, or Ed25519.",
                    standards_mapped=["SOC2-CC6.1", "ISO27001-A.10.1"],
                )
            )

        if age_days > self.MAX_KEY_AGE_DAYS:
            findings.append(
                SecurityFinding(
                    finding_id="CRYPTO-002",
                    category="Key Management",
                    severity=FindingSeverity.HIGH,
                    title="Cryptographic Key Exceeds Rotation Window",
                    description=f"Key {key_id} age is {age_days} days (max allowable: {self.MAX_KEY_AGE_DAYS} days).",
                    remediation="Initiate key rotation via KMS / HSM and revoke legacy key versions.",
                    standards_mapped=["SOC2-CC6.7", "ISO27001-A.10.1.2"],
                )
            )

        return findings

    def audit_api_security_headers(
        self, endpoint: str, headers: dict[str, str]
    ) -> list[SecurityFinding]:
        """Audit HTTP response security headers for OWASP API compliance."""
        findings = []
        h_lower = {k.lower(): v for k, v in headers.items()}

        if "strict-transport-security" not in h_lower:
            findings.append(
                SecurityFinding(
                    finding_id="HDR-001",
                    category="Transport Security",
                    severity=FindingSeverity.HIGH,
                    title="Missing HTTP Strict Transport Security (HSTS)",
                    description=f"Endpoint {endpoint} does not enforce Strict-Transport-Security header.",
                    remediation="Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains'.",
                    standards_mapped=["OWASP-API8", "SOC2-CC6.6"],
                )
            )

        if "content-security-policy" not in h_lower:
            findings.append(
                SecurityFinding(
                    finding_id="HDR-002",
                    category="Content Security",
                    severity=FindingSeverity.MEDIUM,
                    title="Missing Content-Security-Policy (CSP)",
                    description=f"Endpoint {endpoint} does not define a restrictive Content-Security-Policy.",
                    remediation="Define a strict CSP restricting script-src, object-src, and frame-ancestors.",
                    standards_mapped=["OWASP-API7", "ISO27001-A.14.2.5"],
                )
            )

        cors_origin = h_lower.get("access-control-allow-origin", "")
        if cors_origin == "*":
            findings.append(
                SecurityFinding(
                    finding_id="CORS-001",
                    category="Access Control",
                    severity=FindingSeverity.HIGH,
                    title="Permissive Wildcard CORS Configuration",
                    description=f"Endpoint {endpoint} returns 'Access-Control-Allow-Origin: *'.",
                    remediation="Explicitly specify authorized domain origins instead of wildcard reflection.",
                    standards_mapped=["OWASP-API7", "SOC2-CC6.6"],
                )
            )

        return findings

    def audit_cloud_storage_bucket(
        self, bucket_name: str, is_public: bool, encryption_enabled: bool, versioning_enabled: bool
    ) -> list[SecurityFinding]:
        """Audit cloud storage bucket configuration for public access and encryption."""
        findings = []

        if is_public:
            findings.append(
                SecurityFinding(
                    finding_id="CLOUD-001",
                    category="Cloud Posture",
                    severity=FindingSeverity.CRITICAL,
                    title="Public Storage Bucket Exposure",
                    description=f"Bucket {bucket_name} has public read/write access enabled.",
                    remediation="Enable S3/GCS Public Access Block and restrict bucket policies to VPC endpoints.",
                    standards_mapped=["CIS-Benchmark-2.1.5", "SOC2-CC6.6"],
                )
            )

        if not encryption_enabled:
            findings.append(
                SecurityFinding(
                    finding_id="CLOUD-002",
                    category="Data Protection",
                    severity=FindingSeverity.HIGH,
                    title="Missing Server-Side Encryption at Rest",
                    description=f"Bucket {bucket_name} does not enforce default server-side encryption.",
                    remediation="Configure default KMS (SSE-KMS) or provider-managed AES-256 encryption.",
                    standards_mapped=["SOC2-CC6.1", "ISO27001-A.10.1"],
                )
            )

        return findings

    def generate_report(self, all_findings: list[SecurityFinding], total_scanned: int) -> AuditReport:
        """Compile comprehensive security audit report."""
        critical_count = sum(1 for f in all_findings if f.severity == FindingSeverity.CRITICAL)
        high_count = sum(1 for f in all_findings if f.severity == FindingSeverity.HIGH)
        passed = (critical_count == 0) and (high_count == 0)

        return AuditReport(
            passed=passed,
            findings=all_findings,
            total_scanned=total_scanned,
            critical_count=critical_count,
        )
