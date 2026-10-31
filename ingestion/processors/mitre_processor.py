from typing import Dict, List, Any, Tuple, Optional

class MITREProcessor:
    def process_matrix(self, data: Dict[str, Any]) -> Dict[str, List[Tuple[Any, ...]]]:
        tactics: List[Tuple[Any, ...]] = []
        techniques: List[Tuple[Any, ...]] = []
        sub_techniques: List[Tuple[Any, ...]] = []
        mappings: List[Tuple[Any, ...]] = []
        
        tactic_id_map: Dict[str, str] = {}
        objects = data.get('objects', [])

        for obj in objects:
            if obj.get('type') == 'x-mitre-tactic':
                t_id = self._get_external_id(obj)
                short_name = obj.get('x_mitre_shortname', '')
                tactic_id_map[short_name] = t_id

                tactics.append((
                    t_id, 
                    obj.get('name'), 
                    obj.get('description', ''), 
                    self._get_url(obj)
                ))

        for obj in objects:
            if obj.get('type') == 'attack-pattern':
                tech_id = self._get_external_id(obj)
                is_sub = obj.get('x_mitre_is_subtechnique', False)
                
                for phase in obj.get('kill_chain_phases', []):
                    tactic_sn = phase.get('phase_name')
                    if tactic_sn in tactic_id_map:
                        mappings.append((tech_id, tactic_id_map[tactic_sn]))

                base_info = (
                    tech_id, 
                    obj.get('name'), 
                    obj.get('description', ''), 
                    self._get_url(obj)
                )
                
                if is_sub:
                    parent_id = tech_id.split('.')[0] if '.' in tech_id else None
                    sub_techniques.append((*base_info, parent_id))
                else:
                    techniques.append((*base_info, None))

        return {
            'tactics': tactics,
            'techniques': techniques,
            'sub_techniques': sub_techniques,
            'mappings': mappings
        }

    def _get_external_id(self, obj: Dict[str, Any]) -> str:
        for ref in obj.get('external_references', []):
            if ref.get('source_name') in ['mitre-attack', 'mobile-attack', 'ics-attack']:
                return ref.get('external_id', 'unknown')
        return "unknown"

    def _get_url(self, obj: Dict[str, Any]) -> str:
        for ref in obj.get('external_references', []):
            if ref.get('source_name') in ['mitre-attack', 'mobile-attack', 'ics-attack']:
                return ref.get('url', '')
        return ""