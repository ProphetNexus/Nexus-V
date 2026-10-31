from dataclasses import dataclass, astuple
from typing import Any, List, Dict, Optional

@dataclass
class CVERecord:
    cve_id: str
    vuln_status: str
    published: str
    last_modified: str
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

    def to_tuple(self):
        return astuple(self)

class NVDProcessor:
    cvss_versions = [
        ('cvssMetricV40', 'V4.0'), ('cvssMetricV31', 'V3.1'),
        ('cvssMetricV30', 'V3.0'), ('cvssMetricV2',  'V2.0')
    ]
    valid_statuses = {'Received', 'Awaiting Analysis', 'Undergoing Analysis', 'Analyzed', 'Modified', 'Rejected', 'Deferred'}
    valid_severities = {'NONE', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'}

    def extract_cvss(self, metrics: Dict[str, Any]) -> tuple:
        if not metrics:
            return ('V3.1', None, 'NONE', None, None, None)

        for m_key, m_display in self.cvss_versions:
            m_list = metrics.get(m_key)
            if isinstance(m_list, list) and m_list:
                m = m_list[0]
                cvss_data = m.get('cvssData', {})
                sev = (cvss_data.get('baseSeverity') or m.get('baseSeverity') or 'NONE').upper()
                if sev not in self.valid_severities: sev = 'NONE'
                
                return (
                    m_display,
                    cvss_data.get('baseScore') or m.get('baseScore'),
                    sev,
                    cvss_data.get('vectorString'),
                    m.get('exploitabilityScore'),
                    m.get('impactScore')
                )
        return ('V3.1', None, 'NONE', None, None, None)

    def process_batch(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, List[tuple]]:
        main_records, product_records = [], []
        
        for item in vulnerabilities:
            try:
                cve = item['cve']
                cve_id = cve['id']
                
                v_ver, v_score, v_sev, v_vec, v_exp, v_imp = self.extract_cvss(cve.get('metrics', {}))
                
                desc_list = cve.get('descriptions', [])
                desc = next((d.get('value') for d in desc_list if d.get('lang') == 'en'), "")
                desc = " ".join(desc.split()).replace('\x00', '')
                
                status = cve.get('vulnStatus', 'Received')
                if status not in self.valid_statuses: status = 'Received'

                for cfg in cve.get('configurations', []):
                    for node in cfg.get('nodes', []):
                        for m in node.get('cpeMatch', []):
                            product_records.append((
                                cve_id, m['criteria'][:512],
                                m.get('versionStartIncluding'), 
                                m.get('versionEndExcluding'), 
                                m.get('versionEndIncluding')
                            ))

                record = CVERecord(
                    cve_id=cve_id,
                    vuln_status=status,
                    published=cve.get('published'),
                    last_modified=cve.get('lastModified'),
                    cvss_version=v_ver,
                    score=v_score,
                    severity=v_sev,
                    cvss_vector=v_vec,
                    exploitability_score=v_exp,
                    impact_score=v_imp,
                    cisa_kev_date=cve.get('cisaExploitAdd'),
                    cisa_action=cve.get('cisaRequiredAction'),
                    cisa_vulnerability_name=cve.get('cisaVulnerabilityName'),
                    source_identifier=cve.get('sourceIdentifier', 'NVD'),
                    source_type=cve.get('sourceType', 'Secondary'),
                    description=desc,
                    weaknesses=",".join([d.get('value') for w in cve.get('weaknesses', []) for d in w.get('description', []) if d.get('value')]),
                    references_urls=",".join([r.get('url') for r in cve.get('references', []) if r.get('url')])
                )
                main_records.append(record.to_tuple())
            except Exception:
                continue 
        
        return {'main': main_records, 'products': product_records}