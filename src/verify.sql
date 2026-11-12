-- P2 verification. Run: sqlite3 "<db>" < src/verify.sql
.headers on
.mode column

SELECT 'foreign key violations' AS check_name, COUNT(*) AS n FROM pragma_foreign_key_check;

-- Row count per raw part (official documentation states 2,540,044 total)
SELECT source_part, COUNT(*) AS n FROM flow GROUP BY source_part
UNION ALL SELECT 'total', COUNT(*) FROM flow;

-- Label consistency: attack rows must have a family, normal rows must not
SELECT label, SUM(attack_cat_id IS NULL) AS no_family, SUM(attack_cat_id IS NOT NULL) AS has_family
FROM flow GROUP BY label;

-- Raw spelling -> canonical family (the label-cleaning record)
SELECT v.raw_label AS raw_label_quoted, c.name AS canonical, v.row_count
FROM attack_label_variant v JOIN attack_category c USING (attack_cat_id)
ORDER BY c.name, v.row_count DESC;

-- Family counts after cleaning
SELECT c.name AS family, COUNT(*) AS flows
FROM flow f JOIN attack_category c USING (attack_cat_id) GROUP BY c.name ORDER BY flows DESC;

-- Definition-file-driven columns
SELECT COUNT(*) AS feature_defs FROM feature_def;

-- Exact duplicate flows (explains any gap vs the documented total)
SELECT COUNT(*) AS duplicate_groups, SUM(n) - COUNT(*) AS extra_rows FROM (
    SELECT COUNT(*) AS n FROM flow
    GROUP BY src_host_id, sport, dst_host_id, dsport, protocol_id, stime, ltime, sbytes, dbytes, label
    HAVING n > 1);

SELECT 'unparsed ports' AS check_name, SUM(sport IS NULL) + SUM(dsport IS NULL) AS n FROM flow;
