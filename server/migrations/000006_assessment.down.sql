-- 000006_assessment 回滚
--
-- 外键依赖逆序：risk_items / assessment_assets → assessments。
-- 两张子表都指向 assessments（属本迁移），另有指向 assets / vulnerabilities
-- 的**逻辑引用**（刻意未建外键，见 up 约束 3），因此无需考虑外部依赖。

DROP TABLE IF EXISTS `assessment_assets`;
DROP TABLE IF EXISTS `risk_items`;
DROP TABLE IF EXISTS `assessments`;
