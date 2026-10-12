-- 000007_remediation —— P6 整改跟踪
--
-- 落地两张表：
--   remediations      整改单（业务事实，不属于任何一次评估）
--   remediation_logs  整改单的流转与变更记录（可追溯性的载体）
--
-- 关键设计约束（改动前请先读完）：
--
--   1. **整改单的业务身份是 (asset_id, vuln_id)，不是 risk_item_id。**
--      这是本迁移最重要的一条，理由来自 000006 约束 5 的另一面：
--      P4 的 calculate 是「先清后写」，重算一次 risk_items 的 id **整批变化**。
--      若整改单外键指向 risk_item_id，重算之后单子依然在、指向的风险项
--      却已不存在 —— 而且**没有任何报错**。整改单会变成一份查不到来源、
--      也无法判断是否还成立的记录，且这种损坏是静默的。
--      整改单回答的是「某台资产上的某个漏洞要修」这个业务问题，
--      它是**业务事实**，不该被「重新算了一遍」改写。
--
--      assessment_id / risk_item_id 因此降级为**发现出处**：只用于回答
--      「这张单子是哪次评估发现的」。出处允许失效（评估被删、风险项被
--      重算覆盖），不影响单子本身。这与 000006 约束 3「保留 ID 用于追溯、
--      展示一律走快照列」是同一手法。
--
--   2. **「同一 (资产, 漏洞) 同时只允许一张未闭环单」，用生成列 + 唯一索引表达。**
--      MySQL 没有部分索引（partial index），而应用层「先查后插」在并发下
--      存在竞态窗口（两个人同时点建单 → 两张单）。
--      做法：生成列 active_key —— 未闭环时 = "asset_id:vuln_id"，
--      闭环（closed / accepted）后 = NULL。MySQL 的唯一索引把多个 NULL
--      视为互不相同（000004 约束 2 与 000006 约束 4 都踩过这条规则），
--      于是「历史上同一对象反复整改过几次」不会互相冲突，
--      而「同时存在两张未闭环单」被数据库直接拒绝。
--      ⚠️ 生成列只能引用**在它之前定义**的列，故它必须排在
--      asset_id / vuln_id / status 之后。
--      ⚠️ 状态机里 closed / accepted 是**终态**，不允许再流转回未闭环态
--      —— 否则会出现「闭环后重新打开」与「唯一索引」争取同一把锁的
--      诡异组合。漏洞复发时应当**新建一张单**（这正是 §1 的语义）。
--
--   3. **四个 ID（asset_id / vuln_id / assessment_id / risk_item_id）都不建外键。**
--      与 000006 约束 3 同理：整改单是业务事实。删掉一条误录入的漏洞、
--      删掉一次不再需要的评估，都不应该连带抹掉「有人承诺过要修它」这件事；
--      反过来建 RESTRICT 又会因为一张整改单而让用户删不掉一条漏洞。
--      折中：ID 保留用于跳转与聚合，展示一律走下面的快照列。
--
--   4. **remediation_logs 只对「自己的单子」建 CASCADE。**
--      这条与约束 3 不矛盾：流转日志是单子的**派生数据**，单子这是
--      主体；主体没了，日志没有独立存在意义（同 000006 约束 5 对
--      assessment_id 的处理）。
--
--   5. **逾期（overdue）刻意不落库。**
--      它是「due_date 与今天的关系」，是一个**算得出来的派生量**。
--      落一个布尔列就需要一个每日定时任务去翻，而任务一旦停跑，
--      库里的数字就静默变成错的 —— 且没有任何地方会报警。
--      读的时候算，则永远是对的。表里只存 due_date（DATE）。

-- ---------------------------------------------------------------- 整改单
CREATE TABLE IF NOT EXISTS `remediations` (
  `id`             BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '主键',
  -- 业务身份（见约束 1）：逻辑引用，不建外键，展示走下面的快照列。
  `asset_id`       BIGINT UNSIGNED NOT NULL COMMENT '资产 ID（逻辑引用，未建外键）',
  `vuln_id`        BIGINT UNSIGNED NOT NULL COMMENT '漏洞 ID（逻辑引用，未建外键）',
  -- 发现出处（见约束 1）：只用于追溯，允许失效。
  `assessment_id`  BIGINT UNSIGNED NULL DEFAULT NULL COMMENT '发现它的评估任务 ID（出处，允许失效）',
  `risk_item_id`   BIGINT UNSIGNED NULL DEFAULT NULL COMMENT '建单时的风险项 ID（出处，重算后即失效）',
  -- 快照列：目标被删除 / 评估被重算后，单子仍然完整可读。
  `asset_name`     VARCHAR(128)    NOT NULL DEFAULT ''     COMMENT '资产名称快照',
  `asset_ip`       VARCHAR(64)     NOT NULL DEFAULT ''     COMMENT '资产 IP 快照',
  `vuln_title`     VARCHAR(255)    NOT NULL DEFAULT ''     COMMENT '漏洞名称快照',
  `vuln_cve_ids`   VARCHAR(512)    NOT NULL DEFAULT ''     COMMENT 'CVE 编号快照',
  `risk_level`     VARCHAR(16)     NOT NULL DEFAULT ''     COMMENT '发现时的风险等级快照（very_high / high / ...）',
  `risk_value_r`   DECIMAL(8,3)    NOT NULL DEFAULT 0.000  COMMENT '发现时的风险值 R 快照',
  -- 单子内容。
  `title`          VARCHAR(255)    NOT NULL DEFAULT ''     COMMENT '整改单标题（默认取漏洞名，可改）',
  `description`    VARCHAR(1000)   NOT NULL DEFAULT ''     COMMENT '整改要求 / 说明',
  `resolution`     VARCHAR(1000)   NOT NULL DEFAULT ''     COMMENT '整改结论（闭环或风险接受时填写）',
  `status`         VARCHAR(16)     NOT NULL DEFAULT 'pending' COMMENT 'pending / in_progress / resolved / closed / accepted',
  `assignee_id`    BIGINT UNSIGNED NULL DEFAULT NULL       COMMENT '整改负责人 ID（逻辑引用）',
  `due_date`       DATE            NULL DEFAULT NULL       COMMENT '整改期限；NULL = 未设期限（永远不算逾期）',
  `created_by`     BIGINT UNSIGNED NULL DEFAULT NULL       COMMENT '创建者 ID',
  `closed_at`      DATETIME(3)     NULL DEFAULT NULL       COMMENT '进入终态（closed / accepted）的时间',
  `created_at`     DATETIME(3)     NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `updated_at`     DATETIME(3)     NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
  -- 未闭环唯一键（见约束 2）。⚠️ 必须定义在 asset_id / vuln_id / status 之后。
  `active_key`     VARCHAR(64) GENERATED ALWAYS AS (
                     IF(`status` IN ('pending', 'in_progress', 'resolved'),
                        CONCAT(`asset_id`, ':', `vuln_id`),
                        NULL)
                   ) STORED COMMENT '未闭环唯一键 = "asset_id:vuln_id"；闭环后为 NULL（NULL 互不相等）',
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_remediations_active` (`active_key`),
  KEY `idx_remediations_status_due` (`status`, `due_date`),
  KEY `idx_remediations_assignee` (`assignee_id`, `status`),
  KEY `idx_remediations_target` (`asset_id`, `vuln_id`),
  KEY `idx_remediations_level` (`risk_level`),
  KEY `idx_remediations_created_at` (`created_at`)
) ENGINE = InnoDB
  DEFAULT CHARSET = utf8mb4
  COLLATE = utf8mb4_0900_ai_ci
  COMMENT = '整改单（资产 × 漏洞的工作项）';

-- ------------------------------------------------------------ 流转记录
CREATE TABLE IF NOT EXISTS `remediation_logs` (
  `id`             BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '主键',
  `remediation_id` BIGINT UNSIGNED NOT NULL COMMENT '所属整改单',
  -- action 三值：create（建单）/ update（改字段）/ transition（状态流转）。
  -- 刻意把字段改动也记进同一张时间线：详情页要按时间读下来，
  -- 分成两张表（一张状态、一张字段）会让「那天到底发生了什么」需要拼两次。
  `action`         VARCHAR(16)     NOT NULL COMMENT 'create / update / transition',
  `from_status`    VARCHAR(16)     NOT NULL DEFAULT ''     COMMENT '流转前状态；空串 = 本次不是状态流转',
  `to_status`      VARCHAR(16)     NOT NULL DEFAULT ''     COMMENT '流转后状态；空串 = 本次不是状态流转',
  `note`           VARCHAR(500)    NOT NULL DEFAULT ''     COMMENT '说明（打回与风险接受**必须**填写，见 service 层）',
  -- operator_name 冗余存储：账号改名后历史记录仍要能对应到人（同 audit_logs 的理由）。
  `operator_id`    BIGINT UNSIGNED NULL DEFAULT NULL,
  `operator_name`  VARCHAR(64)     NOT NULL DEFAULT '',
  `created_at`     DATETIME(3)     NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  PRIMARY KEY (`id`),
  -- (remediation_id, id) 而不是 (remediation_id, created_at)：时间戳可能同毫秒，
  -- 而详情页的时间线必须有一个**全序**，否则同一毫秒的两条记录顺序不定。
  KEY `idx_remediation_logs_rem` (`remediation_id`, `id`),
  CONSTRAINT `fk_remediation_logs_remediation` FOREIGN KEY (`remediation_id`)
    REFERENCES `remediations` (`id`) ON DELETE CASCADE
) ENGINE = InnoDB
  DEFAULT CHARSET = utf8mb4
  COLLATE = utf8mb4_0900_ai_ci
  COMMENT = '整改单流转与变更记录';
