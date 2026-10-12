-- 000001_init —— P0 基线迁移
--
-- P0 阶段只落地 system_configs（系统配置 KV 表）：
--   1. 让迁移链路端到端跑通并可验证
--   2. 该表本身为后续「风险模型权重 / 阈值可配置」所必需
-- 业务表（users / assets / assessments / ...）在 P1 起按阶段增量添加。

CREATE TABLE IF NOT EXISTS `system_configs` (
  `id`           BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '主键',
  `config_key`   VARCHAR(128)    NOT NULL                COMMENT '配置键',
  `config_value` TEXT            NOT NULL                COMMENT '配置值（JSON 或纯文本）',
  `value_type`   VARCHAR(16)     NOT NULL DEFAULT 'string' COMMENT '值类型：string/json/int/bool',
  `description`  VARCHAR(255)    NOT NULL DEFAULT ''     COMMENT '配置说明',
  `editable`     TINYINT(1)      NOT NULL DEFAULT 1      COMMENT '是否允许在界面修改',
  `created_at`   DATETIME(3)     NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `updated_at`   DATETIME(3)     NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_system_configs_config_key` (`config_key`)
) ENGINE = InnoDB
  DEFAULT CHARSET = utf8mb4
  COLLATE = utf8mb4_0900_ai_ci
  COMMENT = '系统配置';

-- 预置 GB/T 20984 相乘法的默认权重与阈值（P4 读取，界面可改）
INSERT INTO `system_configs` (`config_key`, `config_value`, `value_type`, `description`, `editable`)
VALUES
  ('risk.model',            'gb_t_20984_multiplication', 'string', '当前启用的风险评估模型', 0),
  ('risk.asset_weight',     '1.0',                       'string', '资产价值权重系数',       1),
  ('risk.threshold.very_high', '20',                     'int',    '风险值 ≥ 该值判定为「很高」', 1),
  ('risk.threshold.high',      '12',                     'int',    '风险值 ≥ 该值判定为「高」',   1),
  ('risk.threshold.medium',    '6',                      'int',    '风险值 ≥ 该值判定为「中」',   1),
  ('risk.threshold.low',       '2',                      'int',    '风险值 ≥ 该值判定为「低」',   1)
ON DUPLICATE KEY UPDATE `config_key` = `config_key`;
