from typing import List, Dict
import time
import mysql.connector

class Upsert:
    def __init__(self, db_pool):
        self.db_pool = db_pool

    def process_and_save(self, batch_data: Dict[str, List[tuple]]):
        if not batch_data or not batch_data.get('main'):
            return

        conn = None
        cursor = None
        label = "Initialization"
        try:
            conn = self.db_pool.get_connection()
            cursor = conn.cursor()

            cve_sql = """
                INSERT INTO `cves` (
                    `cve_id`, `vuln_status`, `published`, `last_modified`, `cvss_version`, 
                    `score`, `severity`, `cvss_vector`, `exploitability_score`, `impact_score`, 
                    `cisa_kev_date`, `cisa_action`, `cisa_vulnerability_name`, `source_identifier`, 
                    `source_type`, `description`, `weaknesses`, `references_urls`
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE 
                    `vuln_status` = VALUES(`vuln_status`),
                    `last_modified` = VALUES(`last_modified`),
                    `cvss_version` = VALUES(`cvss_version`),
                    `score` = VALUES(`score`),
                    `severity` = VALUES(`severity`),
                    `cvss_vector` = VALUES(`cvss_vector`),
                    `exploitability_score` = VALUES(`exploitability_score`),
                    `impact_score` = VALUES(`impact_score`),
                    `cisa_kev_date` = VALUES(`cisa_kev_date`),
                    `cisa_action` = VALUES(`cisa_action`),
                    `cisa_vulnerability_name` = VALUES(`cisa_vulnerability_name`),
                    `description` = VALUES(`description`),
                    `weaknesses` = VALUES(`weaknesses`),
                    `references_urls` = VALUES(`references_urls`)
            """

            cpe_sql = """
                INSERT INTO `cve_affected_products` (
                    `cve_id`, `cpe_string`, `version_start_including`, 
                    `version_end_excluding`, `version_end_including`
                ) VALUES (%s, %s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE 
                    `version_start_including` = VALUES(`version_start_including`),
                    `version_end_excluding` = VALUES(`version_end_excluding`),
                    `version_end_including` = VALUES(`version_end_including`)
            """

            tasks = [(cve_sql, batch_data['main'], "CVEs")]
            if batch_data.get('products'):
                tasks.append((cpe_sql, batch_data['products'], "Products"))

            for sql, data, label in tasks:
                stack = [data]
                
                while stack:
                    current_chunk = stack.pop()
                    if not current_chunk:
                        continue
                        
                    try:
                        cursor.executemany(sql, current_chunk)
                    except mysql.connector.Error as err:
                        # Handle Deadlocks (1213) or Lock Timeouts (1205) with a retry
                        if err.errno in (1213, 1205):
                            time.sleep(0.5)
                            stack.append(current_chunk)
                            continue
                            
                        if len(current_chunk) == 1:
                            raise ValueError(f"Database rejected record in {label} (ID: {current_chunk[0][0]}): {err.msg}") from err
                        
                        # Split and retry to isolate the bad record
                        mid = len(current_chunk) // 2
                        stack.append(current_chunk[mid:])
                        stack.append(current_chunk[:mid])

            conn.commit()

        except Exception as e:
            if conn:
                conn.rollback()
            raise RuntimeError(f"NVD Data Persistence failed during {label} processing") from e
        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()

    def save_mitre_framework(self, data: Dict[str, List[tuple]]):
        if not data or not data.get('tactics'):
            return

        conn = None
        cursor = None
        label = "Initialization"
        try:
            conn = self.db_pool.get_connection()
            cursor = conn.cursor()

            tactic_sql = """
                INSERT INTO `attack_tactics` (`tactic_id`, `name`, `description`, `url`)
                VALUES (%s, %s, %s, %s) 
                ON DUPLICATE KEY UPDATE `name`=VALUES(`name`), `description`=VALUES(`description`), `url`=VALUES(`url`)
            """
            tech_sql = """
                INSERT INTO `attack_techniques` (`technique_id`, `name`, `description`, `url`, `parent_technique_id`)
                VALUES (%s, %s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE `name`=VALUES(`name`), `description`=VALUES(`description`), `url`=VALUES(`url`), `parent_technique_id`=VALUES(`parent_technique_id`)
            """
            map_sql = "INSERT IGNORE INTO `technique_tactics` (`technique_id`, `tactic_id`) VALUES (%s, %s)"

            tasks = [
                (tactic_sql, data.get('tactics', []), "Tactics"),
                (tech_sql, data.get('techniques', []), "Techniques"),
                (tech_sql, data.get('sub_techniques', []), "Sub-Techniques"),
                (map_sql, data.get('mappings', []), "Mappings")
            ]

            for sql, dataset, label in tasks:
                stack = [dataset]
                while stack:
                    current = stack.pop()
                    if not current: continue
                    try:
                        cursor.executemany(sql, current)
                    except mysql.connector.Error as err:
                        if err.errno in (1213, 1205):
                            time.sleep(0.2)
                            stack.append(current)
                            continue
                        if len(current) == 1:
                            raise ValueError(f"MITRE framework record rejected for {label}: {err.msg}") from err
                        mid = len(current) // 2
                        stack.append(current[mid:])
                        stack.append(current[:mid])

            conn.commit()
        except Exception as e:
            if conn:
                conn.rollback()
            raise RuntimeError(f"MITRE ATT&CK Framework sync failed at {label} stage") from e
        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()