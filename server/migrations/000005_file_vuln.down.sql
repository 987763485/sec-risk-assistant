-- 000005_file_vuln 回滚
--
-- 外键依赖逆序：vuln_asset_links → vulnerabilities → scan_files。
-- vuln_asset_links 同时指向 vulnerabilities 与 assets（assets 属于
-- 000004，不在本次回滚范围内，只删自己引入的三张表）。

DROP TABLE IF EXISTS `vuln_asset_links`;
DROP TABLE IF EXISTS `vulnerabilities`;
DROP TABLE IF EXISTS `scan_files`;
