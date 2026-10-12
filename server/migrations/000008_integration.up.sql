-- 000008_integration —— P7 扩展模块预留（三方情报源 + MCP）
--
-- 落地两张表：
--   integrations  三方情报源的**接入配置**（用户可控的出站目标）
--   vuln_intel    按漏洞聚合的情报**快照**（漏洞的派生属性）
--
-- 关键设计约束（改动前请先读完）：
--
--   1. **情报接在漏洞层，不接整改单层。**
--      整改单的粒度是「(资产, 漏洞) 这一个组合」，而情报描述的是**漏洞本身**
--      （CVE 的 CVSS 分、描述、参考链接），与「哪台机器上有它」无关。
--      挂在整改单上会让同一条 CVE 在 N 台资产上被拉 N 次、存 N 份，
--      且其中任意一份更新都不会传到其余 N-1 份。
--      因此外键指向 vulnerabilities，一次拉取的结果对该漏洞的所有整改单可见。
--
--   2. **凭据永不入库。**
--      integrations 表里只存 `credential_env` —— 凭据所在的**环境变量名**，
--      而不是凭据本身。理由有两条，任一条都足够：
--        · 库是备份、导出、只读副本都会流出的东西；环境变量不会。
--        · 审计日志与错误信息一旦带上凭据就是灾难（本项目已有 sanitize 兜底，
--          但「不写进去」永远比「写了再想办法擦掉」可靠）。
--      ⚠️ 刻意**不做**「任意环境变量名」的自由度（不加 `credential_value`
--      兜底、不在界面上提供「直接填密钥」）：那等于开出一个
--      「读取进程内任意环境变量」的原语，任何能改集成配置的人都能把
--      `SR_AUTH_JWT_SECRET` 写进去再触发一次拉取，从而把密钥原样发到自己的服务器。
--      服务层只放行白名单前缀（见 service/integration.go 的 credentialEnvAllowed）。
--
--   3. **base_url 是用户可控的出站目标，SSRF 是 P7 的头号风险。**
--      这一列的存在本身就把「请求哪些地址」的决定权交给了配置者。
--      防护不在数据库层（SQL 拦不住），而在 pkg/intelfeed：
--      只允许 http/https、**解析域名后校验 IP 而不是校验字符串**
--      （否则 `0x7f.1`、`[::ffff:127.0.0.1]`、`2130706433` 这类写法可以绕过
--      基于字符串的黑名单）、拒绝回环与全部私有网段、限制响应体大小与超时。
--      见 docs/07 §SSRF 与 service/integration.go 的调用点。
--
--   4. **拉取历史刻意不建表。**
--      审计日志已用 `integration.fetch` 动作码承载「谁在什么时候拉了哪条 CVE、
--      成功还是失败」。再建一张 run 表就是同一事实的第二个落点，
--      而两处必然漂移（审计写入失败不回滚业务、历史表清理不影响审计）。
--      表里只保留**最近一次**运行态（last_* 四列），供列表页展示。
--
--   5. **运行态与配置同表，updated_at 因此是「行更新时间」而非「配置变更时间」。**
--      拆表会让列表页为了一行「最近一次拉取」去 JOIN，而 P7 不做拉取历史，
--      运行态只有一行。代价是每次拉取都会刷新 updated_at，
--      界面**不得**把 updated_at 呈现为「配置最后修改时间」。
--
--   6. **vuln_intel 的唯一键必须含 cve_id。**
--      vulnerabilities.cve_ids 是**逗号分隔串**（一条漏洞可挂多个 CVE），
--      一次拉取会对该漏洞的每个 CVE 各落一条。
--      若唯一键只有 (vuln_id, source)，第二条 CVE 的情报会覆盖第一条 ——
--      表现为「拉了两个 CVE，库里只剩一个」，且不报错。
--
--   7. **vuln_intel 对漏洞建 CASCADE。**
--      与 000005 里 vulnerabilities → scan_files 的 RESTRICT 形成对照，
--      判据是「谁是主体」：情报是漏洞的**派生属性**（漏洞没了，情报没有
--      独立存在意义），而漏洞是文件的**业务事实**（文件删了，漏洞记录
--      仍要解释「它从哪来」，所以 RESTRICT + 服务层 409 引导）。

-- ------------------------------------------------------------ 情报源配置
CREATE TABLE IF NOT EXISTS `integrations` (
  `id`             BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '主键',
  -- name 而不是 code：一个类型可以配多个实例（同一个 nvd 适配器指向
  -- 两个不同的代理入口），因此需要一个用户可读的区分标识。
  `name`           VARCHAR(64)     NOT NULL COMMENT '集成名称（唯一，用于区分同类型的多个实例）',
  `type`           VARCHAR(32)     NOT NULL COMMENT '适配器类型：nvd / local（决定用哪个 intelfeed.Feed 实现）',
  `base_url`       VARCHAR(255)    NOT NULL DEFAULT '' COMMENT '上游基址。⚠️ 用户可控的出站目标，必须过 SSRF 校验（见约束 3）',
  `credential_env` VARCHAR(64)     NOT NULL DEFAULT '' COMMENT '凭据所在的**环境变量名**，不是凭据本身（见约束 2）；空串 = 无需凭据',
  `enabled`        TINYINT(1)      NOT NULL DEFAULT 1  COMMENT '是否启用。停用后不进候选、不允许拉取',
  `timeout_ms`     INT UNSIGNED    NOT NULL DEFAULT 10000 COMMENT '单次拉取超时（毫秒）。服务层另有上限，超出即收敛',
  -- —— 运行态：只保留最近一次（见约束 4、5）——
  `last_run_at`    DATETIME(3)     NULL DEFAULT NULL   COMMENT '最近一次拉取时间',
  `last_status`    VARCHAR(16)     NOT NULL DEFAULT '' COMMENT 'success / failed；空串 = 从未拉取过',
  `last_error`     VARCHAR(255)    NOT NULL DEFAULT '' COMMENT '最近一次失败原因（**不得写入凭据**）',
  `last_latency_ms` INT UNSIGNED   NULL DEFAULT NULL   COMMENT '最近一次拉取耗时（毫秒）',
  `created_by`     BIGINT UNSIGNED NULL DEFAULT NULL   COMMENT '创建者 ID（逻辑引用，未建外键）',
  `created_at`     DATETIME(3)     NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `updated_at`     DATETIME(3)     NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3) COMMENT '行更新时间（含运行态写入，见约束 5）',
  PRIMARY KEY (`id`),
  -- 名称唯一由数据库兜底，而不是「服务层先查后插」：后者在并发下存在竞态窗口，
  -- 两个人同时提交同名集成会双双通过检查（同 000007 约束 2 的教训）。
  UNIQUE KEY `uk_integrations_name` (`name`),
  KEY `idx_integrations_type` (`type`),
  KEY `idx_integrations_enabled` (`enabled`)
) ENGINE = InnoDB
  DEFAULT CHARSET = utf8mb4
  COLLATE = utf8mb4_0900_ai_ci
  COMMENT = '三方情报源接入配置（凭据只存环境变量名）';

-- -------------------------------------------------------------- 情报快照
CREATE TABLE IF NOT EXISTS `vuln_intel` (
  `id`              BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '主键',
  `vuln_id`         BIGINT UNSIGNED NOT NULL COMMENT '所属漏洞（见约束 1、7）',
  -- source 存的是**集成类型**而不是 integrations.id：类型是适配器的不变量，
  -- 而集成配置可以被删除重建。若存 id，删掉集成配置会让历史情报变成
  -- 指向一个不存在的配置的行（同 000007 约束 1 的教训：身份不能建在会被重算/删除的表上）。
  `source`          VARCHAR(32)     NOT NULL COMMENT '情报源标识（集成类型：nvd / local）',
  `cve_id`          VARCHAR(64)     NOT NULL DEFAULT '' COMMENT '本条情报对应的 CVE 编号；无 CVE 时为空串（见约束 6）',
  `title`           VARCHAR(255)    NOT NULL DEFAULT '' COMMENT '上游给的标题',
  `description`     TEXT            NULL COMMENT '上游给的描述',
  `severity`        VARCHAR(16)     NOT NULL DEFAULT 'unknown' COMMENT 'critical / high / medium / low / unknown',
  `cvss_score`      DECIMAL(3,1)    NULL DEFAULT NULL COMMENT 'CVSS 基础分 0.0–10.0；NULL = 上游未给',
  `cvss_vector`     VARCHAR(128)    NOT NULL DEFAULT '' COMMENT 'CVSS 向量串',
  `published_at`    DATETIME(3)     NULL DEFAULT NULL COMMENT '上游的发布时间',
  `references_json` JSON            NULL COMMENT '参考链接数组',
  `raw_json`        JSON            NULL COMMENT '上游原始片段（已截断）。保留它是为了「界面显示的与上游一致」可被追溯',
  `fetched_at`      DATETIME(3)     NOT NULL COMMENT '本次抓取时间（不等于 published_at）',
  `created_at`      DATETIME(3)     NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `updated_at`      DATETIME(3)     NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_vuln_intel_identity` (`vuln_id`, `source`, `cve_id`),
  KEY `idx_vuln_intel_vuln` (`vuln_id`, `fetched_at`),
  KEY `idx_vuln_intel_cve` (`cve_id`),
  CONSTRAINT `fk_vuln_intel_vuln` FOREIGN KEY (`vuln_id`)
    REFERENCES `vulnerabilities` (`id`) ON DELETE CASCADE
) ENGINE = InnoDB
  DEFAULT CHARSET = utf8mb4
  COLLATE = utf8mb4_0900_ai_ci
  COMMENT = '漏洞情报快照（外部拉取结果，删除漏洞即随之清理）';
