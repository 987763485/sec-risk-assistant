-- 000008_integration 回滚
--
-- 外键依赖逆序：vuln_intel → vulnerabilities，因此必须先删 vuln_intel
-- （它是引用方）。integrations 没有任何外键关系，与两个表都无关，
-- 顺序放在最后只是为了读起来与外键链一致。
--
-- vulnerabilities 本身不归本迁移管，回滚时不能被带走。

DROP TABLE IF EXISTS `vuln_intel`;
DROP TABLE IF EXISTS `integrations`;
