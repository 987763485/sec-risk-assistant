-- 000005_file_vuln —— P3 扫描文件与漏洞清单
--
-- 落地三张表：
--   scan_files       上传的扫描报告（元数据 + SHA-256 去重）
--   vulnerabilities  漏洞清单（解析产出 + 手工录入共用一张表）
--   vuln_asset_links 漏洞 ↔ 资产 关联
--
-- 关键设计约束（改动前请先读完）：
--
--   1. **scan_files.sha256 全局唯一，上传即去重。** 同一内容的文件重复
--      上传不会产生第二行：服务层按哈希查到已有记录后直接幂等返回。
--      这既是存储上的省钱（上传目录里同一份内容永远只有一份物理文件），
--      也是审计上的诚实——「同一个文件被谁传了几次」由 audit_logs 记，
--      不由 scan_files 记。
--
--   2. **存储路径 storage_path 故意不含扩展名。** 原始文件名只存在
--      original_name 里用于下载时的 Content-Disposition。落盘路径是
--      YYYYMM/<32 位十六进制>（crypto/rand），月分目录避免单目录堆几十万个
--      文件；下载响应强制 application/octet-stream —— 「文件以什么名字存在
--      磁盘上」与「文件以什么名字给用户下载」是两件事，混为一谈就是路径
--      穿越与内容嗅探的入口。默认根目录 ./storage/uploads（SR_STORAGE_UPLOAD_DIR）。
--
--   3. **vulnerabilities.source_file_id 可空：NULL 表示手工录入。**
--      解析产出与手工录入共用一张表，是因为 P4 评估引擎消费漏洞时
--      不应该关心漏洞的来源；一个 `source_file_id IS NULL` 的判断
--      就能区分「扫描得出」与「人工登记」，不需要第二张表。
--
--   4. **severity 是 1–5 的整数，severity_raw 保留扫描器原始串。**
--      P4 的风险计算只认整数 V 值；但 Nessus 的 High / OpenVAS 的
--      8.0 (CVSS) 这些原始信息丢掉就无法追溯映射是否合理，所以两列并存。
--      映射规则（Critical→5 / High→4 / Medium→3 / Low→2 / Info→1，
--      CVSS 按分值切档）写在解析器层，不在 SQL 里。
--
--   5. **文件删除用 RESTRICT：还有漏洞引用的文件删不掉。** 漏洞是
--      P4 评估的输入，文件一删「这些漏洞从哪来」就断了线。服务层先查
--      引用计数给出可读的 409，这个外键是数据库层的兜底。
--      反过来 vuln_asset_links 两侧都是 CASCADE：删漏洞清掉它的链接、
--      删资产清掉指向它的链接——链接是派生数据，跟着主体走是正确语义
--      （资产删除本身是「修正误录入」的物理删除，见 000004 约束 5）。
--
--   6. **cve_ids 逗号分隔存一列，不建子表。** 一条 ReportItem 可能挂
--      多个 CVE，但业务上从不按单个 CVE 增删改查——它们是同一条漏洞
--      的别名。为「别名」建表是过度设计；需要按 CVE 搜时 LIKE 前缀
--      匹配足够（本系统不是 CVE 数据库）。

-- ---------------------------------------------------------------- 扫描文件
CREATE TABLE IF NOT EXISTS `scan_files` (
  `id`           BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '主键',
  `sha256`       CHAR(64)        NOT NULL                COMMENT '内容哈希，全局唯一；上传去重的判据',
  `original_name` VARCHAR(255)   NOT NULL                COMMENT '用户上传时的原始文件名（仅用于下载时的展示）',
  `storage_path` VARCHAR(255)    NOT NULL                COMMENT '落盘相对路径 YYYYMM/<32位十六进制>，无扩展名（见约束 2）',
  `size_bytes`   BIGINT UNSIGNED NOT NULL                COMMENT '文件字节数',
  `mime_type`    VARCHAR(64)     NOT NULL DEFAULT ''     COMMENT '嗅探出的 MIME 类型',
  `format`       VARCHAR(16)     NOT NULL DEFAULT ''     COMMENT 'nessus / openvas / excel；上传时尚未解析时为空串',
  `parse_status` VARCHAR(16)     NOT NULL DEFAULT 'unparsed' COMMENT 'unparsed=未解析 / parsed=已入库 / failed=解析失败',
  `parsed_at`    DATETIME(3)     NULL     DEFAULT NULL   COMMENT '解析入库时间',
  `vuln_count`   INT UNSIGNED    NOT NULL DEFAULT 0      COMMENT '该文件解析出的漏洞条数（commit 时写入）',
  `uploaded_by`  BIGINT UNSIGNED NULL     DEFAULT NULL   COMMENT '上传者 ID',
  `created_at`   DATETIME(3)     NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `updated_at`   DATETIME(3)     NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_scan_files_sha256` (`sha256`),
  KEY `idx_scan_files_parse_status` (`parse_status`, `id`),
  KEY `idx_scan_files_uploaded_by` (`uploaded_by`),
  KEY `idx_scan_files_created_at` (`created_at`)
) ENGINE = InnoDB
  DEFAULT CHARSET = utf8mb4
  COLLATE = utf8mb4_0900_ai_ci
  COMMENT = '上传的扫描报告文件';

-- ---------------------------------------------------------------- 漏洞清单
CREATE TABLE IF NOT EXISTS `vulnerabilities` (
  `id`             BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '主键',
  `source_file_id` BIGINT UNSIGNED NULL     DEFAULT NULL   COMMENT '来源文件；NULL 表示手工录入',
  `title`          VARCHAR(255)    NOT NULL                COMMENT '漏洞名称',
  `cve_ids`        VARCHAR(512)    NOT NULL DEFAULT ''     COMMENT 'CVE 编号，英文逗号分隔（一条漏洞可挂多个）',
  `severity_raw`   VARCHAR(64)     NOT NULL DEFAULT ''     COMMENT '扫描器原始等级串，如 High / 8.0 (CVSS)，仅追溯用',
  `severity`       TINYINT UNSIGNED NOT NULL DEFAULT 3    COMMENT '严重程度 1–5，对应风险模型里的脆弱性 V',
  `description`    TEXT            NULL                    COMMENT '漏洞描述',
  `solution`       TEXT            NULL                    COMMENT '修复建议',
  `host_ip`        VARCHAR(64)     NOT NULL DEFAULT ''     COMMENT '受影响主机 IP（自动关联资产的判据）',
  `port`           SMALLINT UNSIGNED NULL DEFAULT NULL     COMMENT '受影响端口，NULL 表示与端口无关',
  `protocol`       VARCHAR(16)     NOT NULL DEFAULT ''     COMMENT '协议 tcp / udp，空串表示未注明',
  `service`        VARCHAR(64)     NOT NULL DEFAULT ''     COMMENT '服务名，如 https / ssh',
  `created_by`     BIGINT UNSIGNED NULL     DEFAULT NULL   COMMENT '创建者 ID（解析写入时为发起解析的用户）',
  `created_at`     DATETIME(3)     NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `updated_at`     DATETIME(3)     NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
  PRIMARY KEY (`id`),
  KEY `idx_vulnerabilities_source_file` (`source_file_id`),
  KEY `idx_vulnerabilities_severity` (`severity`, `id`),
  KEY `idx_vulnerabilities_host_ip` (`host_ip`),
  KEY `idx_vulnerabilities_title` (`title`),
  -- RESTRICT 而不是 CASCADE：文件删除必须先清掉漏洞（服务层 409 引导），
  -- 静默级联会把「漏洞从哪来」这段事实抹掉。
  CONSTRAINT `fk_vulnerabilities_source_file` FOREIGN KEY (`source_file_id`)
    REFERENCES `scan_files` (`id`) ON DELETE RESTRICT
) ENGINE = InnoDB
  DEFAULT CHARSET = utf8mb4
  COLLATE = utf8mb4_0900_ai_ci
  COMMENT = '漏洞清单（解析产出 + 手工录入）';

-- ---------------------------------------------------------- 漏洞-资产关联
CREATE TABLE IF NOT EXISTS `vuln_asset_links` (
  `id`         BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '主键',
  `vuln_id`    BIGINT UNSIGNED NOT NULL COMMENT '漏洞 ID',
  `asset_id`   BIGINT UNSIGNED NOT NULL COMMENT '资产 ID',
  `matched_by` VARCHAR(16)     NOT NULL DEFAULT 'auto' COMMENT 'auto=按 IP 自动匹配 / manual=手动挂载',
  `created_by` BIGINT UNSIGNED NULL DEFAULT NULL COMMENT '操作人（manual 时有意义）',
  `created_at` DATETIME(3)     NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  PRIMARY KEY (`id`),
  -- 同一漏洞对同一资产只允许一条链接：重复解析、手动重挂都落到
  -- INSERT IGNORE / ON DUPLICATE 上，而不是先查后插的竞态窗口。
  UNIQUE KEY `uk_vuln_asset` (`vuln_id`, `asset_id`),
  KEY `idx_vuln_asset_asset` (`asset_id`),
  -- 两侧 CASCADE：链接是派生数据，主体删除时跟着走（见头部约束 5）。
  CONSTRAINT `fk_vuln_asset_vuln` FOREIGN KEY (`vuln_id`)
    REFERENCES `vulnerabilities` (`id`) ON DELETE CASCADE,
  CONSTRAINT `fk_vuln_asset_asset` FOREIGN KEY (`asset_id`)
    REFERENCES `assets` (`id`) ON DELETE CASCADE
) ENGINE = InnoDB
  DEFAULT CHARSET = utf8mb4
  COLLATE = utf8mb4_0900_ai_ci
  COMMENT = '漏洞与资产的关联';
