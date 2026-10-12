-- 000006_assessment —— P4 风险评估引擎
--
-- 落地三张表：
--   assessments       评估任务（含配置快照与汇总）
--   risk_items        风险项（资产 × 漏洞，A/T/V/R 四列齐存）
--   assessment_assets 资产级汇总（矩阵下钻的第一层）
--
-- 关键设计约束（改动前请先读完）：
--
--   1. **配置快照 config_snapshot 是这张表的核心。** 权重与阈值存在
--      system_configs 里且界面可改；若不快照，改一次阈值就会**静默改写
--      所有历史评估的档位** —— 已发出的报告与库里的数据对不上，而这是
--      最难排查的一类事故（数据看起来都对，只是和昨天不一样了）。
--      快照进 assessments 行之后，历史评估永久可复现：重算用的是任务
--      创建时的配置，不是「现在的」配置。
--
--   2. **risk_items 把 A / T / V / R 四列齐存，不只存 R。** 只存结果等于
--      放弃可解释性：下钻时用户要问「这台机器为什么是 20 分」，必须能当场
--      拆出 A=4 × T=5 × V=1。这与 000005 保留 severity_raw 是同一条理由 ——
--      丢了中间量，事后无法复核规则本身是否合理。
--
--   3. **risk_items.asset_id / vuln_id 刻意不建外键，只存逻辑引用 + 快照字段。**
--      风险项是**时点快照**，不是实时派生数据（与约束 1 的 config_snapshot
--      同类）。若建 CASCADE，删掉一条漏洞会连带抹掉历史评估里的一行，
--      报告的「当时结论」就被悄悄改写了；若建 RESTRICT，又会因为一份
--      三个月前的评估而让用户删不掉一条误录入的漏洞。
--      折中结果是：ID 保留用于下钻跳转，展示一律走快照列
--      （asset_name / asset_ip / vuln_title）；目标被删时跳转 404，
--      但报告仍然完整可读。这条与 000004 约束 5 里「P4 接入引用检查」
--      的初版设想不同，属于实现期修正，理由见 docs/11。
--
--   4. **vuln_id 收紧为 NOT NULL（初版计划写的是可空）。** 两个原因：
--      其一，MySQL 唯一索引把多个 NULL 视为互不相同（000004 约束 2 踩过
--      这个坑），vuln_id 可空则 uk_risk_items_target 对「无漏洞风险项」
--      完全失效，重复计算会堆出重复行；其二，当前 D1 决策下风险项粒度
--      就是「资产 × 漏洞」，没有无漏洞来源的输入路径。将来真要做手工
--      风险项，应当新增迁移而不是让唯一索引从一开始就形同虚设。
--
--   5. **assessment_id 建外键并 CASCADE。** 这一条与约束 3 并不矛盾：
--      评估任务被删除，说明用户不再需要这份评估，它的结果行是**派生数据**，
--      跟着主体走是正确语义（同 000005 约束 5 对 vuln_asset_links 的处理）。
--      而资产 / 漏洞是外部的**事实来源**，删掉它们不该改写历史结论。
--
--   6. **金额式的数值一律 DECIMAL，不用 FLOAT。** R = A × T × V 要参与
--      阈值比较（≥20 / ≥12 / ≥6 / ≥2），浮点表示误差落在阈值边界上就是
--      一条错误的等级。落库用 DECIMAL，引擎内部用放大 1000 倍的定点整数。

-- ---------------------------------------------------------------- 评估任务
CREATE TABLE IF NOT EXISTS `assessments` (
  `id`            BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '主键',
  `name`          VARCHAR(128)    NOT NULL                COMMENT '评估任务名称',
  `description`   VARCHAR(512)    NOT NULL DEFAULT ''     COMMENT '说明',
  `status`        VARCHAR(16)     NOT NULL DEFAULT 'draft' COMMENT 'draft=草稿（未计算）/ calculated=已计算',
  `scope_type`    VARCHAR(16)     NOT NULL DEFAULT 'all'  COMMENT '评估范围：all=全部资产 / group=按资产组 / custom=手工指定资产',
  `scope_ref`     JSON            NULL     DEFAULT NULL   COMMENT '范围明细：group 存组 ID 数组，custom 存资产 ID 数组；all 时为 NULL',
  `model_key`     VARCHAR(64)     NOT NULL DEFAULT 'gb_t_20984_multiplication' COMMENT '风险模型标识',
  `default_threat_code` VARCHAR(64) NOT NULL DEFAULT ''   COMMENT '任务级默认威胁（dictionaries category=threat 的 code）；空串表示未指定',
  `config_snapshot` JSON          NULL     DEFAULT NULL   COMMENT '计算时的权重与阈值快照（见约束 1）',
  `assets_count`  INT UNSIGNED    NOT NULL DEFAULT 0      COMMENT '纳入计算的资产数',
  `risk_items_count` INT UNSIGNED NOT NULL DEFAULT 0      COMMENT '风险项条数',
  `max_risk`      DECIMAL(8,3)    NULL     DEFAULT NULL   COMMENT '最大风险值 R',
  `level_counts`  JSON            NULL     DEFAULT NULL   COMMENT '各等级条数，形如 {"very_high":2,...}',
  `calculated_at` DATETIME(3)     NULL     DEFAULT NULL   COMMENT '最近一次计算时间',
  `created_by`    BIGINT UNSIGNED NULL     DEFAULT NULL   COMMENT '创建者 ID',
  `created_at`    DATETIME(3)     NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `updated_at`    DATETIME(3)     NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
  PRIMARY KEY (`id`),
  KEY `idx_assessments_status` (`status`, `id`),
  KEY `idx_assessments_created_by` (`created_by`),
  KEY `idx_assessments_created_at` (`created_at`)
) ENGINE = InnoDB
  DEFAULT CHARSET = utf8mb4
  COLLATE = utf8mb4_0900_ai_ci
  COMMENT = '风险评估任务';

-- ---------------------------------------------------------------- 风险项
CREATE TABLE IF NOT EXISTS `risk_items` (
  `id`             BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '主键',
  `assessment_id`  BIGINT UNSIGNED NOT NULL COMMENT '所属评估任务',
  -- 逻辑引用（见约束 3）：不建外键，展示走下面的快照列。
  `asset_id`       BIGINT UNSIGNED NOT NULL COMMENT '资产 ID（逻辑引用，未建外键）',
  `vuln_id`        BIGINT UNSIGNED NOT NULL COMMENT '漏洞 ID（逻辑引用，未建外键）',
  -- 快照列：目标被删除后报告仍然可读。
  `asset_name`     VARCHAR(128)    NOT NULL DEFAULT ''     COMMENT '资产名称快照',
  `asset_ip`       VARCHAR(64)     NOT NULL DEFAULT ''     COMMENT '资产 IP 快照',
  `vuln_title`     VARCHAR(255)    NOT NULL DEFAULT ''     COMMENT '漏洞名称快照',
  `vuln_cve_ids`   VARCHAR(512)    NOT NULL DEFAULT ''     COMMENT 'CVE 编号快照',
  `vuln_severity_raw` VARCHAR(64)  NOT NULL DEFAULT ''     COMMENT '扫描器原始等级串快照',
  -- 威胁来源：default=取任务级默认威胁 / manual=在风险项上逐项覆盖。
  -- 保留来源与 000005 的 matched_by 同理：能溯源才敢批量改回去。
  `threat_code`    VARCHAR(64)     NOT NULL DEFAULT ''     COMMENT '威胁码',
  `threat_name`    VARCHAR(128)    NOT NULL DEFAULT ''     COMMENT '威胁名称快照',
  `threat_source`  VARCHAR(16)     NOT NULL DEFAULT 'default' COMMENT 'default=任务级 / manual=逐项覆盖',
  -- 原始档位：矩阵维度用它们（1–5 整数，不受权重影响，结构稳定）。
  `importance`     TINYINT UNSIGNED NOT NULL DEFAULT 3     COMMENT '资产重要性原始档位 1–5（矩阵 X 轴）',
  `severity`       TINYINT UNSIGNED NOT NULL DEFAULT 3     COMMENT '漏洞严重程度原始档位 1–5（矩阵 Y 轴）',
  -- 参与计算的四个量（见约束 6：DECIMAL，不用 FLOAT）。
  `asset_value_a`  DECIMAL(6,3)    NOT NULL COMMENT 'A：资产价值 = 重要性 × 资产价值权重系数',
  `threat_weight_t` DECIMAL(6,3)   NOT NULL COMMENT 'T：威胁权重',
  `vuln_weight_v`  DECIMAL(6,3)    NOT NULL COMMENT 'V：脆弱性权重（取自 vulnerabilities.severity）',
  `risk_value_r`   DECIMAL(8,3)    NOT NULL COMMENT 'R = A × T × V',
  `risk_level`     VARCHAR(16)     NOT NULL COMMENT 'very_high / high / medium / low / very_low',
  `created_at`     DATETIME(3)     NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `updated_at`     DATETIME(3)     NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
  PRIMARY KEY (`id`),
  -- 一次评估里同一 (资产, 漏洞) 只能有一行（约束 4 讨论了为什么 vuln_id 必须 NOT NULL）。
  UNIQUE KEY `uk_risk_items_target` (`assessment_id`, `asset_id`, `vuln_id`),
  KEY `idx_risk_items_matrix` (`assessment_id`, `importance`, `severity`),
  KEY `idx_risk_items_level` (`assessment_id`, `risk_level`),
  KEY `idx_risk_items_r` (`assessment_id`, `risk_value_r`),
  CONSTRAINT `fk_risk_items_assessment` FOREIGN KEY (`assessment_id`)
    REFERENCES `assessments` (`id`) ON DELETE CASCADE
) ENGINE = InnoDB
  DEFAULT CHARSET = utf8mb4
  COLLATE = utf8mb4_0900_ai_ci
  COMMENT = '风险评估项（资产 × 漏洞）';

-- ------------------------------------------------------------ 资产级汇总
CREATE TABLE IF NOT EXISTS `assessment_assets` (
  `id`            BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '主键',
  `assessment_id` BIGINT UNSIGNED NOT NULL COMMENT '所属评估任务',
  `asset_id`      BIGINT UNSIGNED NOT NULL COMMENT '资产 ID（逻辑引用，同 risk_items 约束 3）',
  `asset_name`    VARCHAR(128)    NOT NULL DEFAULT ''     COMMENT '资产名称快照',
  `asset_ip`      VARCHAR(64)     NOT NULL DEFAULT ''     COMMENT '资产 IP 快照',
  `importance`    TINYINT UNSIGNED NOT NULL DEFAULT 3     COMMENT '资产重要性原始档位 1–5',
  `asset_value_a` DECIMAL(6,3)    NOT NULL DEFAULT 0.000  COMMENT '该资产的 A 值',
  -- 资产级风险 = 该资产下最严重的漏洞决定（木桶原则的变体：一台机器能
  -- 被打穿到什么程度，由它最弱的那一环决定，而不是平均值）。
  `risk_value`    DECIMAL(8,3)    NOT NULL DEFAULT 0.000  COMMENT '该资产的最大风险值 R',
  `risk_level`    VARCHAR(16)     NOT NULL DEFAULT 'very_low' COMMENT '该资产的风险等级',
  `risk_items_count` INT UNSIGNED NOT NULL DEFAULT 0      COMMENT '该资产下的风险项条数',
  `top_item_id`   BIGINT UNSIGNED NULL DEFAULT NULL       COMMENT '最大 R 对应的风险项 ID，供下钻直跳',
  `created_at`    DATETIME(3)     NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `updated_at`    DATETIME(3)     NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_assessment_assets` (`assessment_id`, `asset_id`),
  KEY `idx_assessment_assets_risk` (`assessment_id`, `risk_value`),
  CONSTRAINT `fk_assessment_assets_assessment` FOREIGN KEY (`assessment_id`)
    REFERENCES `assessments` (`id`) ON DELETE CASCADE
) ENGINE = InnoDB
  DEFAULT CHARSET = utf8mb4
  COLLATE = utf8mb4_0900_ai_ci
  COMMENT = '评估的资产级汇总';
