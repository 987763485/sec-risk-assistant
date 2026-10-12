#!/usr/bin/env bash
# ============================================================================
# MySQL 逻辑备份脚本
#
# 用法：
#   bash scripts/db-backup.sh                    # 备份到 backups/
#   BACKUP_DIR=/data/backups bash scripts/db-backup.sh
#
# 说明：
#   - 用 mysqldump 的 --single-transaction 保证 InnoDB 一致性快照，不锁表
#   - 备份文件 gzip 压缩，文件名带时间戳
#   - 自动清理超过保留天数的旧备份（默认 14 天）
# ============================================================================
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

BACKUP_DIR="${BACKUP_DIR:-${ROOT}/backups}"
RETENTION_DAYS="${RETENTION_DAYS:-14}"
STAMP="$(date +%Y%m%d-%H%M%S)"

# 读取 .env（若存在）
if [[ -f .env ]]; then
  # shellcheck disable=SC1091
  set -a; source .env; set +a
fi

DB_NAME="${MYSQL_DATABASE:-sec_risk}"
DB_USER="${MYSQL_USER:-secrisk}"
DB_PASS="${MYSQL_PASSWORD:-secrisk_dev_pwd}"

mkdir -p "${BACKUP_DIR}"
OUT="${BACKUP_DIR}/${DB_NAME}-${STAMP}.sql.gz"

echo "[backup] 开始备份数据库 ${DB_NAME} …"

docker compose exec -T mysql \
  mysqldump \
    --single-transaction \
    --quick \
    --routines \
    --events \
    --triggers \
    --default-character-set=utf8mb4 \
    -u"${DB_USER}" -p"${DB_PASS}" "${DB_NAME}" \
  | gzip -9 > "${OUT}"

SIZE="$(du -h "${OUT}" | cut -f1)"
echo "[backup] ✅ 完成: ${OUT} (${SIZE})"

echo "[backup] 清理 ${RETENTION_DAYS} 天前的旧备份…"
find "${BACKUP_DIR}" -name "${DB_NAME}-*.sql.gz" -type f -mtime "+${RETENTION_DAYS}" -print -delete || true

echo "[backup] 当前备份列表:"
ls -lht "${BACKUP_DIR}" | head -10
