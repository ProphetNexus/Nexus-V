from dataclasses import dataclass
from typing import Any, List, Dict, Optional

@dataclass(slots=True)
class CVERecord:
    cve_id: str
    vuln_status: str
    published: Optional[str]
    last_modified: Optional[str]
    cvss_version: str
    score: Optional[float]
    severity: str
    cvss_vector: Optional[str]
    exploitability_score: Optional[float]
    impact_score: Optional[float]
    cisa_kev_date: Optional[str]
    cisa_action: Optional[str]
    cisa_vulnerability_name: Optional[str]
    source_identifier: str
    source_type: str
    description: str
    weaknesses: str
    references_urls: str

    def to_tuple(self) -> tuple:
        return (
            self.cve_id, self.vuln_status, self.published, self.last_modified,
            self.cvss_version, self.score, self.severity, self.cvss_vector,
            self.exploitability_score, self.impact_score, self.cisa_kev_date,
            self.cisa_action, self.cisa_vulnerability_name, self.source_identifier,
            self.source_type, self.description, self.weaknesses, self.references_urls
        )

class NVDProcessor:
    CVSS_VERSIONS = (
        ('cvssMetricV40', 'V4.0'), ('cvssMetricV31', 'V3.1'),
        ('cvssMetricV30', 'V3.0'), ('cvssMetricV2',  'V2.0')
    )
    VALID_STATUSES = frozenset({
        'Received', 'Awaiting Analysis', 'Undergoing Analysis',
        'Analyzed', 'Modified', 'Rejected', 'Deferred'
    })
    VALID_SEVERITIES = frozenset({'NONE', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'})

    def extract_cvss(self, metrics: Optional[Dict[str, Any]]) -> tuple:
        if not metrics:
            return ('V3.1', None, 'NONE', None, None, None)

        valid_severities = self.VALID_SEVERITIES
        for m_key, m_display in self.CVSS_VERSIONS:
            m_list = metrics.get(m_key)
            if m_list:
                m = next((item for item in m_list if item.get('type') == 'Primary'), m_list[0])
                cvss_data = m.get('cvssData', {})
                
                raw_sev = cvss_data.get('baseSeverity') or m.get('baseSeverity')
                sev = raw_sev.upper() if raw_sev else 'NONE'
                if sev not in valid_severities:
                    sev = 'NONE'

                score = cvss_data.get('baseScore')
                if score is None:
                    score = m.get('baseScore')

                return (
                    m_display,
                    score,
                    sev,
                    cvss_data.get('vectorString'),
                    m.get('exploitabilityScore'),
                    m.get('impactScore')
                )
        return ('V3.1', None, 'NONE', None, None, None)

    def process_batch(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, List[tuple]]:
        main_records = []
        product_records = []
        valid_statuses = self.VALID_STATUSES
        extract_cvss = self.extract_cvss

        for item in vulnerabilities:
            try:
                cve = item['cve']
                cve_id = cve['id']

                v_ver, v_score, v_sev, v_vec, v_exp, v_imp = extract_cvss(cve.get('metrics'))

                desc = ""
                for d in cve.get('descriptions', ()):
                    if d.get('lang') == 'en':
                        val = d.get('value', '')
                        if val:
                            desc = " ".join(val.split()).replace('\x00', '')
                        break

                status = cve.get('vulnStatus', 'Received')
                if status not in valid_statuses:
                    status = 'Received'

                configs = cve.get('configurations')
                if configs:
                    cpes = [
                        (
                            cve_id,
                            m['criteria'][:512],
                            m.get('versionStartIncluding'),
                            m.get('versionEndExcluding'),
                            m.get('versionEndIncluding')
                        )
                        for cfg in configs
                        for node in cfg.get('nodes', ())
                        for m in node.get('cpeMatch', ())
                        if m.get('vulnerable', True) and 'criteria' in m
                    ]
                    if cpes:
                        product_records.extend(cpes)

                weaknesses = ",".join(dict.fromkeys(
                    d['value']
                    for w in cve.get('weaknesses', ())
                    for d in w.get('description', ())
                    if 'value' in d
                ))

                references_urls = ",".join(dict.fromkeys(
                    r['url']
                    for r in cve.get('references', ())
                    if 'url' in r
                ))

                raw_pub = cve.get('published')
                raw_mod = cve.get('lastModified')
                published = raw_pub.replace('T', ' ')[:19] if raw_pub else None
                last_modified = raw_mod.replace('T', ' ')[:19] if raw_mod else None

                main_records.append((
                    cve_id,
                    status,
                    published,
                    last_modified,
                    v_ver,
                    v_score,
                    v_sev,
                    v_vec,
                    v_exp,
                    v_imp,
                    cve.get('cisaExploitAdd'),
                    cve.get('cisaRequiredAction'),
                    cve.get('cisaVulnerabilityName'),
                    cve.get('sourceIdentifier', 'NVD'),
                    cve.get('sourceType', 'Secondary'),
                    desc,
                    weaknesses,
                    references_urls
                ))
            except Exception:
                continue

        return {'main': main_records, 'products': product_records}

