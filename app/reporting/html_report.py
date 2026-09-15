from html import escape

from app.models.report import SecurityReport


class HTMLReportRenderer:
    @staticmethod
    def render(report: SecurityReport) -> str:
        def esc(value: object) -> str:
            return escape(str(value))

        findings: list[str] = []

        for finding in report.findings:
            if finding.cvss is None:
                cvss = "N/A"
            else:
                cvss = f"{finding.cvss.score} (CVSS {finding.cvss.version})"

            evidence: list[str] = []

            for item in finding.evidence:
                label = item.source

                if item.check:
                    label += f" / {item.check}"

                if item.details:
                    details = ", ".join(
                        f"{key}={value}" for key, value in item.details.items()
                    )
                    label += f": {details}"

                evidence.append(f"<li>{esc(label)}</li>")

            evidence_html = (
                "<ul>" + "".join(evidence) + "</ul>" if evidence else "<em>None</em>"
            )

            findings.append(
                '<section class="finding">'
                f"<h3>{esc(finding.title)}</h3>"
                f"<p><strong>Severity:</strong> {esc(finding.severity.value)}</p>"
                f"<p><strong>Description:</strong> {esc(finding.description)}</p>"
                f"<p><strong>CVSS:</strong> {esc(cvss)}</p>"
                f"<p><strong>CVE:</strong> {esc(finding.cve or 'N/A')}</p>"
                f"<p><strong>Port:</strong> {esc(finding.port or 'N/A')}</p>"
                f"<p><strong>Service:</strong> {esc(finding.service or 'N/A')}</p>"
                f"<p><strong>Product:</strong> {esc(finding.product or 'N/A')}</p>"
                f"<p><strong>Version:</strong> {esc(finding.version or 'N/A')}</p>"
                f"<p><strong>Remediation:</strong> "
                f"{esc(finding.remediation or 'N/A')}</p>"
                "<p><strong>Evidence:</strong></p>"
                f"{evidence_html}"
                "</section>"
            )

        findings_html = (
            "".join(findings) if findings else "<p>No security findings.</p>"
        )

        return (
            "<!DOCTYPE html>"
            '<html lang="en">'
            "<head>"
            '<meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width, initial-scale=1">'
            f"<title>AttackLab Security Report - {esc(report.target)}</title>"
            "<style>"
            "body{font-family:Arial,sans-serif;max-width:1100px;"
            "margin:0 auto;padding:32px;background:#f5f7fa;color:#1f2937}"
            ".card,.finding{background:white;border:1px solid #d1d5db;"
            "border-radius:8px;padding:20px;margin:16px 0}"
            ".summary{display:grid;grid-template-columns:"
            "repeat(auto-fit,minmax(140px,1fr));gap:12px}"
            ".metric{background:white;border:1px solid #d1d5db;"
            "border-radius:8px;padding:16px}"
            "</style>"
            "</head>"
            "<body>"
            "<h1>AttackLab Security Report</h1>"
            '<div class="card">'
            "<h2>Assessment</h2>"
            f"<p><strong>Target:</strong> {esc(report.target)}</p>"
            f"<p><strong>Risk level:</strong> "
            f"{esc(report.summary.risk_level)}</p>"
            "</div>"
            '<div class="summary">'
            f'<div class="metric"><strong>Risk Score</strong><br>'
            f"{esc(report.summary.risk_score)}/100</div>"
            f'<div class="metric"><strong>Ports</strong><br>'
            f"{esc(report.summary.total_ports)}</div>"
            f'<div class="metric"><strong>Findings</strong><br>'
            f"{esc(report.summary.total_findings)}</div>"
            f'<div class="metric"><strong>Critical</strong><br>'
            f"{esc(report.summary.critical)}</div>"
            f'<div class="metric"><strong>High</strong><br>'
            f"{esc(report.summary.high)}</div>"
            f'<div class="metric"><strong>Medium</strong><br>'
            f"{esc(report.summary.medium)}</div>"
            f'<div class="metric"><strong>Low</strong><br>'
            f"{esc(report.summary.low)}</div>"
            f'<div class="metric"><strong>Info</strong><br>'
            f"{esc(report.summary.info)}</div>"
            "</div>"
            '<div class="card">'
            "<h2>Findings</h2>"
            f"{findings_html}"
            "</div>"
            "</body>"
            "</html>"
        )
