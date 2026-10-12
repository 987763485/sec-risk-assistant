-- 000002_auth 回滚
--
-- 按外键依赖的逆序删除。audit_logs 无外键，可最先删；
-- user_roles 与 refresh_tokens 都指向 users，必须先于 users 删除。

DROP TABLE IF EXISTS `audit_logs`;
DROP TABLE IF EXISTS `refresh_tokens`;
DROP TABLE IF EXISTS `user_roles`;
DROP TABLE IF EXISTS `users`;
DROP TABLE IF EXISTS `roles`;
