-- 000007_remediation 回滚
--
-- 外键依赖逆序：remediation_logs → remediations。
-- remediations 另有指向 assets / vulnerabilities / assessments / risk_items
-- 的**逻辑引用**（刻意未建外键，见 up 约束 3），因此无需考虑外部依赖。

DROP TABLE IF EXISTS `remediation_logs`;
DROP TABLE IF EXISTS `remediations`;
