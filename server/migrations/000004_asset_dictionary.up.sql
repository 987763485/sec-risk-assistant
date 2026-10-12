-- 000004_asset_dictionary —— P2 资产台账与业务字典
--
-- 落地三张表：
--   asset_groups   资产组（层级树，物化路径）
--   assets         资产台账
--   dictionaries   业务字典（资产类型 + 威胁 / 脆弱性 / 已有措施）
--
-- 关键设计约束（改动前请先读完）：
--
--   1. **asset_groups 用「parent_id + 物化路径 path」表达层级，不用递归 CTE。**
--      子树查询退化为一条 `WHERE path LIKE '/1/4/%'` 的索引扫描，不需要
--      递归；代价是移动节点时要重写整棵子树的 path —— 但那是一条 UPDATE
--      能干完的事（见 repository/assetgroup.go），而子树查询是高频操作。
--
--   2. **parent_id 可空，但唯一性判据用的是生成列 parent_key。**
--      MySQL 唯一索引把多个 NULL 视为互不相同，因此直接对
--      (parent_id, name) 建唯一索引时，**根组重名不会被拦住**——
--      这与 users.email 是同一个陷阱（见 000002 头部约束 2），
--      只是那次靠「默认 NULL」解决，这次必须靠生成列把 NULL 归一为 0。
--
--   3. **assets.asset_type / status 存「码」而不是字典表主键 id。**
--      存码有两个后果，都是想要的：历史资产不会因为字典行被重排而
--      指向别的类型；资产表的行可以脱离字典表单独读懂。
--      代价是字典项的 code 创建后不可变（重命名只会发生在 name 上）。
--
--   4. **字典项「停用」优于「删除」。** 已停用的字典项不再出现在新建
--      表单里，但历史数据引用它时仍然能翻译出中文名。真正删除只允许
--      发生在「非内置 且 未被任何资产引用」的项上。
--
--   5. **资产删除是物理删除，语义是「修正误录入」。** 资产退役请把
--      status 改成 scrapped —— 台账需要留下「这台机器曾经存在、
--      已于某时退役」的事实，而不是把它从历史里抹掉。
--      （被评估记录引用时删除会被拒绝，该检查在 P4 接入。）

-- ---------------------------------------------------------------- 资产组
CREATE TABLE IF NOT EXISTS `asset_groups` (
  `id`          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '主键',
  `parent_id`   BIGINT UNSIGNED NULL     DEFAULT NULL   COMMENT '父组 ID，NULL 表示根组',
  -- 生成列：把 parent_id 的 NULL 归一为 0，让唯一索引对根组也生效。
  -- 用 STORED 而非 VIRTUAL：唯一索引需要物化的值，VIRTUAL 列虽在 MySQL 8
  -- 也支持建索引，但 STORED 在排序与索引扫描上行为更可预期。
  `parent_key`  BIGINT UNSIGNED GENERATED ALWAYS AS (IFNULL(`parent_id`, 0)) STORED
                COMMENT '唯一性判据：parent_id 为 NULL 时归一为 0',
  `name`        VARCHAR(64)     NOT NULL                COMMENT '组名（同一父组下唯一）',
  `path`        VARCHAR(512)    NOT NULL                COMMENT '物化路径，形如 /1/4/9/，含自身',
  `depth`       INT UNSIGNED    NOT NULL DEFAULT 0      COMMENT '层级深度，根组为 0',
  `description` VARCHAR(255)    NOT NULL DEFAULT ''     COMMENT '说明',
  `sort_order`  INT             NOT NULL DEFAULT 0      COMMENT '同级排序，值小的在前',
  `created_by`  BIGINT UNSIGNED NULL     DEFAULT NULL   COMMENT '创建者 ID',
  `created_at`  DATETIME(3)     NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `updated_at`  DATETIME(3)     NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_asset_groups_parent_name` (`parent_key`, `name`),
  KEY `idx_asset_groups_path` (`path`),
  KEY `idx_asset_groups_parent_id` (`parent_id`),
  -- RESTRICT 而不是 CASCADE：有子组时删父组必须失败，不能悄悄连坐。
  -- 服务层会先查一次给出可读的错误码，这里是数据库层的兜底。
  CONSTRAINT `fk_asset_groups_parent` FOREIGN KEY (`parent_id`)
    REFERENCES `asset_groups` (`id`) ON DELETE RESTRICT
) ENGINE = InnoDB
  DEFAULT CHARSET = utf8mb4
  COLLATE = utf8mb4_0900_ai_ci
  COMMENT = '资产组（层级树）';

-- ---------------------------------------------------------------- 资产台账
CREATE TABLE IF NOT EXISTS `assets` (
  `id`          BIGINT UNSIGNED   NOT NULL AUTO_INCREMENT COMMENT '主键',
  `asset_no`    VARCHAR(64)       NULL     DEFAULT NULL   COMMENT '资产编号（业务编号），全局唯一；未填为 NULL 不参与冲突',
  `name`        VARCHAR(128)      NOT NULL                COMMENT '资产名称',
  `asset_type`  VARCHAR(32)       NOT NULL                COMMENT '资产类型码，取自 dictionaries(category=asset_type).code',
  `group_id`    BIGINT UNSIGNED   NULL     DEFAULT NULL   COMMENT '所属资产组',
  `ip_address`  VARCHAR(64)       NOT NULL DEFAULT ''     COMMENT 'IP 地址，兼容 IPv4 / IPv6 / CIDR 写法',
  `port`        SMALLINT UNSIGNED NULL     DEFAULT NULL   COMMENT '端口，NULL 表示未填写',
  `hostname`    VARCHAR(128)      NOT NULL DEFAULT ''     COMMENT '主机名',
  `os_type`     VARCHAR(64)       NOT NULL DEFAULT ''     COMMENT '操作系统',
  `importance`  TINYINT UNSIGNED  NOT NULL DEFAULT 3      COMMENT '重要性 1–5，对应风险模型里的资产价值 A',
  `owner`       VARCHAR(64)       NOT NULL DEFAULT ''     COMMENT '负责人',
  `department`  VARCHAR(64)       NOT NULL DEFAULT ''     COMMENT '归属部门',
  `status`      VARCHAR(16)       NOT NULL DEFAULT 'in_use' COMMENT 'in_use=在用 / idle=闲置 / offline=下线 / scrapped=已报废',
  `tags`        VARCHAR(255)      NOT NULL DEFAULT ''     COMMENT '标签，英文逗号分隔',
  `description` VARCHAR(512)      NOT NULL DEFAULT ''     COMMENT '备注',
  `created_by`  BIGINT UNSIGNED   NULL     DEFAULT NULL   COMMENT '创建者 ID',
  `created_at`  DATETIME(3)       NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `updated_at`  DATETIME(3)       NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
  PRIMARY KEY (`id`),
  -- 单一列唯一索引：多个 NULL 互不冲突，因此「未编号」的资产可以有很多条。
  -- 若改用空串 ''，第二条未编号资产就会被这个索引拦住。
  UNIQUE KEY `uk_assets_asset_no` (`asset_no`),
  KEY `idx_assets_asset_type` (`asset_type`),
  KEY `idx_assets_group_id` (`group_id`),
  KEY `idx_assets_status` (`status`),
  KEY `idx_assets_importance` (`importance`),
  KEY `idx_assets_name` (`name`),
  KEY `idx_assets_ip_address` (`ip_address`),
  -- 综合索引：列表页默认按「资产组 + 状态」筛、按 id 排，覆盖最常见的组合。
  KEY `idx_assets_group_status` (`group_id`, `status`, `id`),
  CONSTRAINT `fk_assets_group` FOREIGN KEY (`group_id`)
    REFERENCES `asset_groups` (`id`) ON DELETE RESTRICT
) ENGINE = InnoDB
  DEFAULT CHARSET = utf8mb4
  COLLATE = utf8mb4_0900_ai_ci
  COMMENT = '资产台账';

-- ---------------------------------------------------------------- 业务字典
CREATE TABLE IF NOT EXISTS `dictionaries` (
  `id`          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '主键',
  `category`    VARCHAR(32)     NOT NULL                COMMENT '类别：asset_type / threat / vulnerability / measure',
  `code`        VARCHAR(64)     NOT NULL                COMMENT '码，**创建后不可变**（资产表按码引用）',
  `name`        VARCHAR(128)    NOT NULL                COMMENT '显示名',
  `weight`      DECIMAL(6,3)    NOT NULL DEFAULT 1.000  COMMENT '权重值：threat=发生可能性 T / vulnerability=严重程度 V / measure=防护有效性；asset_type 不参与风险计算，恒为 1',
  `description` VARCHAR(255)    NOT NULL DEFAULT ''     COMMENT '说明',
  `is_builtin`  TINYINT(1)      NOT NULL DEFAULT 0      COMMENT '内置项：不可删除、不可改码',
  `enabled`     TINYINT(1)      NOT NULL DEFAULT 1      COMMENT '停用后不再出现在新建表单，历史数据仍可解释',
  `sort_order`  INT             NOT NULL DEFAULT 0      COMMENT '同类目内排序，值小的在前',
  `created_at`  DATETIME(3)     NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `updated_at`  DATETIME(3)     NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_dictionaries_category_code` (`category`, `code`),
  KEY `idx_dictionaries_category` (`category`, `enabled`, `sort_order`)
) ENGINE = InnoDB
  DEFAULT CHARSET = utf8mb4
  COLLATE = utf8mb4_0900_ai_ci
  COMMENT = '业务字典';

-- ================================================================ 种子数据
-- 统一用 ON DUPLICATE KEY UPDATE 保证迁移在任意状态下可重复执行。

-- ------------------------------------------------------------ 资产类型
-- asset_type 的 weight 不参与风险计算，统一为默认值 1，此处不显式写列。
INSERT INTO `dictionaries` (`category`, `code`, `name`, `description`, `is_builtin`, `sort_order`)
VALUES
  ('asset_type', 'server',          '服务器',   '物理服务器或虚拟机',       1, 10),
  ('asset_type', 'network_device',  '网络设备', '交换机 / 路由器 / 防火墙等转发设备', 1, 20),
  ('asset_type', 'security_device', '安全设备', 'IDS / IPS / WAF / 堡垒机等', 1, 30),
  ('asset_type', 'database',        '数据库',   '数据库实例或集群',         1, 40),
  ('asset_type', 'middleware',      '中间件',   'Web 容器 / 消息队列 / 缓存等', 1, 50),
  ('asset_type', 'application',     '应用系统', '对内外提供服务的业务系统',  1, 60),
  ('asset_type', 'terminal',        '终端',     '办公 PC / 笔记本 / 移动终端', 1, 70),
  ('asset_type', 'storage',         '存储设备', '磁盘阵列 / NAS / 备份一体机', 1, 80),
  ('asset_type', 'cloud',           '云资源',   '云主机 / 对象存储 / 云数据库等', 1, 90),
  ('asset_type', 'other',           '其他',     '暂未归类的资产',           1, 999)
ON DUPLICATE KEY UPDATE `category` = `category`;

-- ------------------------------------------------------------ 威胁（T：发生可能性）
INSERT INTO `dictionaries` (`category`, `code`, `name`, `weight`, `description`, `is_builtin`, `sort_order`)
VALUES
  ('threat', 'data_leak',        '数据泄露',     4.000, '敏感数据被非授权获取或外泄',        1, 10),
  ('threat', 'dos',              '拒绝服务',     4.000, '服务不可用或被显著拖慢',            1, 20),
  ('threat', 'privilege_escalation', '权限提升', 4.000, '越权获得更高权限',                  1, 30),
  ('threat', 'malware',          '恶意代码',     4.000, '病毒 / 木马 / 勒索软件感染',        1, 40),
  ('threat', 'web_attack',       'Web 应用攻击', 5.000, 'SQL 注入 / XSS / 文件上传等',       1, 50),
  ('threat', 'weak_credential',  '凭证攻击',     5.000, '口令爆破、撞库、默认口令利用',      1, 60),
  ('threat', 'eavesdrop',        '网络窃听',     3.000, '明文传输被截获',                    1, 70),
  ('threat', 'social_engineering','社会工程',    3.000, '钓鱼邮件、电话诈骗等人员攻击',      1, 80),
  ('threat', 'misconfiguration', '配置错误',     4.000, '安全配置缺失或错误',                1, 90),
  ('threat', 'physical_intrusion','物理入侵',    2.000, '机房或终端被物理接触',              1, 100),
  ('threat', 'supply_chain',     '供应链攻击',   3.000, '第三方组件或供应商引入的风险',      1, 110),
  ('threat', 'insider_abuse',    '内部人员滥用', 3.000, '授权人员越界使用权限',              1, 120)
ON DUPLICATE KEY UPDATE `category` = `category`;

-- ------------------------------------------------------ 脆弱性（V：严重程度）
INSERT INTO `dictionaries` (`category`, `code`, `name`, `weight`, `description`, `is_builtin`, `sort_order`)
VALUES
  ('vulnerability', 'weak_password',     '弱口令',         5.000, '口令强度不足或使用默认口令',     1, 10),
  ('vulnerability', 'unpatched',         '未修补漏洞',     5.000, '已知漏洞未及时打补丁',           1, 20),
  ('vulnerability', 'misconfig',         '安全配置缺陷',   4.000, '服务配置不当导致暴露面扩大',     1, 30),
  ('vulnerability', 'plaintext_transport','明文传输',      4.000, '未启用加密传输',                 1, 40),
  ('vulnerability', 'excessive_privilege','权限过宽',      4.000, '最小权限原则未落实',             1, 50),
  ('vulnerability', 'no_backup',         '缺少备份',       4.000, '无备份或备份未验证可恢复',       1, 60),
  ('vulnerability', 'no_logging',        '日志缺失',       3.000, '关键操作无日志、日志不集中',     1, 70),
  ('vulnerability', 'boundary_exposed',  '边界暴露',       5.000, '本应内网的服务暴露在互联网',     1, 80),
  ('vulnerability', 'outdated_component','组件过时',       3.000, '依赖的框架或中间件版本停止维护', 1, 90),
  ('vulnerability', 'single_point',      '单点故障',       3.000, '无冗余，单点失效即业务中断',     1, 100)
ON DUPLICATE KEY UPDATE `category` = `category`;

-- ------------------------------------------------- 已有措施（防护有效性）
INSERT INTO `dictionaries` (`category`, `code`, `name`, `weight`, `description`, `is_builtin`, `sort_order`)
VALUES
  ('measure', 'access_control',  '访问控制',     5.000, '身份鉴别与权限最小化',           1, 10),
  ('measure', 'boundary_defense','边界防护',     5.000, '防火墙 / WAF / 网络分区隔离',    1, 20),
  ('measure', 'intrusion_detect','入侵检测',     4.000, 'IDS / IPS / HIDS 等监测能力',    1, 30),
  ('measure', 'log_audit',       '日志审计',     4.000, '集中日志与定期审计',             1, 40),
  ('measure', 'data_encryption', '数据加密',     5.000, '传输与存储加密',                 1, 50),
  ('measure', 'backup_recovery', '备份恢复',     4.000, '定期备份并演练恢复',             1, 60),
  ('measure', 'patch_management','补丁管理',     4.000, '漏洞修补流程与窗口',             1, 70),
  ('measure', 'security_training','安全培训',    3.000, '人员安全意识培训',               1, 80),
  ('measure', 'vulnerability_scan','漏洞扫描',   3.000, '定期漏洞扫描与整改闭环',         1, 90)
ON DUPLICATE KEY UPDATE `category` = `category`;
