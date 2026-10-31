CREATE DATABASE IF NOT EXISTS `CVE_DB` 
CHARACTER SET utf8mb4 
COLLATE utf8mb4_unicode_ci;

USE `CVE_DB`;

CREATE TABLE IF NOT EXISTS `cves` (
    `cve_id` VARCHAR(25) NOT NULL,
    `vuln_status` ENUM('Received', 'Awaiting Analysis', 'Undergoing Analysis', 'Analyzed', 'Modified', 'Rejected', 'Deferred') DEFAULT 'Received',
    `published` DATETIME NOT NULL,
    `last_modified` DATETIME NOT NULL,
    `cvss_version` ENUM('V2.0', 'V3.0', 'V3.1', 'V4.0') DEFAULT 'V3.1',
    `score` DECIMAL(3, 1),
    `severity` ENUM('NONE', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL') DEFAULT 'NONE',
    `cvss_vector` VARCHAR(255),
    `exploitability_score` DECIMAL(3, 1),
    `impact_score` DECIMAL(3, 1),
    `cisa_kev_date` DATE NULL,
    `cisa_action` TEXT,
    `cisa_vulnerability_name` VARCHAR(255),
    `source_identifier` VARCHAR(255),
    `source_type` VARCHAR(50),
    `description` LONGTEXT, 
    `weaknesses` LONGTEXT,
    `references_urls` LONGTEXT,
    `updated_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (`cve_id`),
    INDEX `idx_published_severity` (`published`, `severity`),
    INDEX `idx_last_mod` (`last_modified`),
    INDEX `idx_cisa_kev` (`cisa_kev_date`),
    FULLTEXT INDEX `idx_description_search` (`description`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `cve_affected_products` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `cve_id` VARCHAR(25) NOT NULL,
    `cpe_string` VARCHAR(512) NOT NULL,
    `version_start_including` VARCHAR(100),
    `version_end_excluding`   VARCHAR(100),
    `version_end_including`   VARCHAR(100),
    `created_at` DATETIME DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT `fk_cve_id` FOREIGN KEY (`cve_id`) REFERENCES `cves` (`cve_id`) ON DELETE CASCADE,
    UNIQUE KEY `unique_cve_product` (`cve_id`, `cpe_string`(255)),
    INDEX `idx_cpe_lookup` (`cpe_string`(255))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `cases` (
    `case_id` VARCHAR(36) NOT NULL,
    `name` VARCHAR(255) NOT NULL,
    `description` TEXT,
    `status` ENUM('active', 'completed', 'archived') DEFAULT 'active',
    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    `updated_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (`case_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `tool_execution_records` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `case_id` VARCHAR(36) NOT NULL,
    `agent_id` VARCHAR(100),
    `tool_name` VARCHAR(255) NOT NULL,
    `description` TEXT,
    `arguments` JSON,
    `execution_start` DATETIME(6) DEFAULT CURRENT_TIMESTAMP(6),
    `execution_end` DATETIME(6) NULL,
    `exit_code` INT,
    `stdout` LONGTEXT,
    `stderr` LONGTEXT,
    `status` ENUM('success', 'failed', 'timeout', 'running') DEFAULT 'running',
    CONSTRAINT `fk_tool_case` FOREIGN KEY (`case_id`) REFERENCES `cases` (`case_id`) ON DELETE CASCADE,
    INDEX `idx_case_tool` (`case_id`, `tool_name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `agent_handoff_records` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `case_id` VARCHAR(36) NOT NULL,
    `source_agent` VARCHAR(100) NOT NULL,
    `target_agent` VARCHAR(100) NOT NULL,
    `handoff_payload` JSON,
    `decision_notes` TEXT,
    `timestamp` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    `parent_handoff_id` INT NULL,
    CONSTRAINT `fk_handoff_case` FOREIGN KEY (`case_id`) REFERENCES `cases` (`case_id`) ON DELETE CASCADE,
    CONSTRAINT `fk_handoff_parent` FOREIGN KEY (`parent_handoff_id`) REFERENCES `agent_handoff_records` (`id`) ON DELETE SET NULL,
    INDEX `idx_case_handoff` (`case_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `claim_verification_records` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `case_id` VARCHAR(36) NOT NULL,
    `agent_id` VARCHAR(100) NOT NULL,
    `claim_type` VARCHAR(100),
    `claim_text` TEXT NOT NULL,
    `confidence_score` DECIMAL(3, 2),
    `evidence_references` JSON,
    `verification_status` ENUM('unverified', 'supported', 'contradicted', 'uncertain') DEFAULT 'unverified',
    `verification_rationale` TEXT,
    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT `fk_claim_case` FOREIGN KEY (`case_id`) REFERENCES `cases` (`case_id`) ON DELETE CASCADE,
    INDEX `idx_case_claim` (`case_id`),
    INDEX `idx_verification` (`verification_status`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- MITRE ATT&CK Framework Tables
CREATE TABLE IF NOT EXISTS `attack_tactics` (
    `tactic_id` VARCHAR(20) NOT NULL, -- e.g., TA0001
    `name` VARCHAR(255) NOT NULL,
    `description` TEXT,
    `url` VARCHAR(255),
    PRIMARY KEY (`tactic_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `attack_techniques` (
    `technique_id` VARCHAR(20) NOT NULL, -- e.g., T1566 or T1566.001
    `name` VARCHAR(255) NOT NULL,
    `description` TEXT,
    `url` VARCHAR(255),
    `parent_technique_id` VARCHAR(20) NULL, -- Self-reference for sub-techniques
    PRIMARY KEY (`technique_id`),
    CONSTRAINT `fk_parent_technique` FOREIGN KEY (`parent_technique_id`) REFERENCES `attack_techniques` (`technique_id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `technique_tactics` (
    `technique_id` VARCHAR(20) NOT NULL,
    `tactic_id` VARCHAR(20) NOT NULL,
    PRIMARY KEY (`technique_id`, `tactic_id`),
    CONSTRAINT `fk_tt_technique` FOREIGN KEY (`technique_id`) REFERENCES `attack_techniques` (`technique_id`) ON DELETE CASCADE,
    CONSTRAINT `fk_tt_tactic` FOREIGN KEY (`tactic_id`) REFERENCES `attack_tactics` (`tactic_id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;