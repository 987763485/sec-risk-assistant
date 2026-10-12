-- 000002_auth —— P1 权限、会话与审计
--
-- 落地五张表：
--   roles                       角色字典（admin / assessor / auditor）
--   users                       账号主体
--   user_roles                  账号 ↔ 角色 关联
--   refresh_tokens              刷新令牌（落库，支持轮换与吊销）
--   audit_logs                  审计日志
--
-- 关键设计约束（改动前请先读完）：
--   1. **不物理删除用户**。DELETE /api/users/:id 的语义是「禁用」
--      （status='disabled'），以维持审计日志与后续评估记录的外键完整性。
--   2. **users.email 允许 NULL 且带唯一索引**。MySQL 唯一索引中多个 NULL
--      互不冲突，而空串 '' 会互相冲突，故默认值必须是 NULL 而非 ''。
--   3. **refresh_tokens 只存 SHA-256 十六进制摘要**，明文刷新令牌不落任何
--      持久化介质。即使数据库被拖库，攻击者也无法据此伪造会话。
--   4. **permissions 不入库**。内置角色的权限码在代码中定义为常量
--      （internal/auth/rbac.go），避免「数据库被改一行就提权」的风险面。
--   5. audit_logs.user_id **刻意不建外键**：审计记录的留存优先级高于
--      账号本身，不应因为账号变动而丢失或级联删除。

-- ---------------------------------------------------------------- 角色字典
CREATE TABLE IF NOT EXISTS `roles` (
  `id`          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '主键',
  `code`        VARCHAR(32)     NOT NULL                COMMENT '角色码：admin/assessor/auditor',
  `name`        VARCHAR(64)     NOT NULL                COMMENT '角色名称',
  `description` VARCHAR(255)    NOT NULL DEFAULT ''     COMMENT '角色职责说明',
  `is_builtin`  TINYINT(1)      NOT NULL DEFAULT 0      COMMENT '内置角色：不可删除、不可改码',
  `created_at`  DATETIME(3)     NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `updated_at`  DATETIME(3)     NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_roles_code` (`code`)
) ENGINE = InnoDB
  DEFAULT CHARSET = utf8mb4
  COLLATE = utf8mb4_0900_ai_ci
  COMMENT = '角色字典';

-- ---------------------------------------------------------------- 账号主体
CREATE TABLE IF NOT EXISTS `users` (
  `id`                    BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '主键',
  `username`              VARCHAR(64)     NOT NULL                COMMENT '登录名，创建后不可变',
  `display_name`          VARCHAR(64)     NOT NULL DEFAULT ''     COMMENT '显示名',
  `email`                 VARCHAR(128)    NULL     DEFAULT NULL   COMMENT '邮箱，NULL 不参与唯一性冲突',
  `password_hash`         VARCHAR(255)    NOT NULL                COMMENT 'argon2id PHC 字符串',
  `status`                VARCHAR(16)     NOT NULL DEFAULT 'active' COMMENT 'active=启用 / disabled=禁用',
  `must_change_password`  TINYINT(1)      NOT NULL DEFAULT 0      COMMENT '下次登录必须改密',
  `failed_login_attempts` INT UNSIGNED    NOT NULL DEFAULT 0      COMMENT '连续登录失败次数，成功即清零',
  `locked_until`          DATETIME(3)     NULL     DEFAULT NULL   COMMENT '锁定截止时间，NULL 表示未锁定',
  `last_login_at`         DATETIME(3)     NULL     DEFAULT NULL   COMMENT '最近成功登录时间',
  `last_login_ip`         VARCHAR(64)     NOT NULL DEFAULT ''     COMMENT '最近成功登录 IP',
  `password_changed_at`   DATETIME(3)     NULL     DEFAULT NULL   COMMENT '最近改密时间',
  `created_by`            BIGINT UNSIGNED NULL     DEFAULT NULL   COMMENT '创建者 ID，引导账号为 NULL',
  `created_at`            DATETIME(3)     NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `updated_at`            DATETIME(3)     NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_users_username` (`username`),
  UNIQUE KEY `uk_users_email` (`email`),
  KEY `idx_users_status` (`status`)
) ENGINE = InnoDB
  DEFAULT CHARSET = utf8mb4
  COLLATE = utf8mb4_0900_ai_ci
  COMMENT = '账号';

-- ------------------------------------------------------------ 账号角色关联
CREATE TABLE IF NOT EXISTS `user_roles` (
  `user_id`    BIGINT UNSIGNED NOT NULL COMMENT '账号 ID',
  `role_id`    BIGINT UNSIGNED NOT NULL COMMENT '角色 ID',
  `created_at` DATETIME(3)     NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  PRIMARY KEY (`user_id`, `role_id`),
  KEY `idx_user_roles_role_id` (`role_id`),
  CONSTRAINT `fk_user_roles_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE,
  CONSTRAINT `fk_user_roles_role` FOREIGN KEY (`role_id`) REFERENCES `roles` (`id`) ON DELETE CASCADE
) ENGINE = InnoDB
  DEFAULT CHARSET = utf8mb4
  COLLATE = utf8mb4_0900_ai_ci
  COMMENT = '账号角色关联';

-- ---------------------------------------------------------------- 刷新令牌
CREATE TABLE IF NOT EXISTS `refresh_tokens` (
  `id`            BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '主键',
  `user_id`       BIGINT UNSIGNED NOT NULL                COMMENT '归属账号',
  `token_hash`    CHAR(64)        NOT NULL                COMMENT 'SHA-256 十六进制摘要（明文不落库）',
  `family_id`     CHAR(36)        NOT NULL                COMMENT '轮换链标识（UUID），同一次登录的所有后代共享',
  `issued_at`     DATETIME(3)     NOT NULL                COMMENT '签发时间',
  `expires_at`    DATETIME(3)     NOT NULL                COMMENT '过期时间',
  `used_at`       DATETIME(3)     NULL DEFAULT NULL       COMMENT '被用于换取新令牌的时间',
  `revoked_at`    DATETIME(3)     NULL DEFAULT NULL       COMMENT '吊销时间',
  `revoke_reason` VARCHAR(32)     NOT NULL DEFAULT ''     COMMENT 'logout/rotated/reuse_detected/password_changed/admin',
  `client_ip`     VARCHAR(64)     NOT NULL DEFAULT ''     COMMENT '签发时客户端 IP',
  `user_agent`    VARCHAR(255)    NOT NULL DEFAULT ''     COMMENT '签发时 User-Agent（截断至 255）',
  `created_at`    DATETIME(3)     NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_refresh_tokens_token_hash` (`token_hash`),
  KEY `idx_refresh_tokens_user_id` (`user_id`),
  KEY `idx_refresh_tokens_family_id` (`family_id`),
  KEY `idx_refresh_tokens_expires_at` (`expires_at`),
  CONSTRAINT `fk_refresh_tokens_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE
) ENGINE = InnoDB
  DEFAULT CHARSET = utf8mb4
  COLLATE = utf8mb4_0900_ai_ci
  COMMENT = '刷新令牌';

-- ---------------------------------------------------------------- 审计日志
CREATE TABLE IF NOT EXISTS `audit_logs` (
  `id`          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '主键',
  `user_id`     BIGINT UNSIGNED NULL     DEFAULT NULL   COMMENT '操作人 ID（未登录操作留空）',
  `username`    VARCHAR(64)     NOT NULL DEFAULT ''     COMMENT '操作人登录名（冗余，防改名后失真）',
  `action`      VARCHAR(64)     NOT NULL                COMMENT '动作码，如 auth.login / user.create',
  `resource`    VARCHAR(64)     NOT NULL DEFAULT ''     COMMENT '资源类型，如 user / assessment',
  `resource_id` VARCHAR(64)     NOT NULL DEFAULT ''     COMMENT '资源标识',
  `method`      VARCHAR(8)      NOT NULL DEFAULT ''     COMMENT 'HTTP 方法',
  `path`        VARCHAR(255)    NOT NULL DEFAULT ''     COMMENT '请求路径',
  `status_code` INT             NOT NULL DEFAULT 0      COMMENT '响应状态码',
  `client_ip`   VARCHAR(64)     NOT NULL DEFAULT ''     COMMENT '客户端 IP',
  `user_agent`  VARCHAR(255)    NOT NULL DEFAULT ''     COMMENT '客户端 UA（截断）',
  `detail`      JSON            NULL     DEFAULT NULL   COMMENT '变更明细（前后值等）',
  `request_id`  VARCHAR(64)     NOT NULL DEFAULT ''     COMMENT '请求链路 ID',
  `created_at`  DATETIME(3)     NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  PRIMARY KEY (`id`),
  KEY `idx_audit_logs_user_id` (`user_id`),
  KEY `idx_audit_logs_action` (`action`),
  KEY `idx_audit_logs_created_at` (`created_at`),
  KEY `idx_audit_logs_resource` (`resource`, `resource_id`)
) ENGINE = InnoDB
  DEFAULT CHARSET = utf8mb4
  COLLATE = utf8mb4_0900_ai_ci
  COMMENT = '审计日志';

-- ------------------------------------------------------------ 内置角色种子
-- 权限码不在此处声明（见文件头约束 4），这里只落地角色身份本身。
-- 用 ON DUPLICATE KEY UPDATE 保证迁移在任意状态下可重复执行。
INSERT INTO `roles` (`code`, `name`, `description`, `is_builtin`)
VALUES ('admin', '系统管理员', '全权：用户与角色管理、系统设置、审计日志、全部业务操作', 1),
       ('assessor', '评估员', '业务全流程：资产、字典、文件、漏洞、评估、整改、报告；不含用户管理与审计日志', 1),
       ('auditor', '审计员', '全站只读，含审计日志与系统设置；不具备任何写权限', 1)
ON DUPLICATE KEY UPDATE `code` = `code`;
