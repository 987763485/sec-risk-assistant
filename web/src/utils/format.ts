/**
 * 展示层格式化工具。
 */

/** 后端所有时间字段都是 RFC3339 字符串 */
function toDate(value: string | null | undefined): Date | null {
  if (!value) return null
  const d = new Date(value)
  return Number.isNaN(d.getTime()) ? null : d
}

/** 格式化为 `YYYY-MM-DD HH:mm:ss`；空值返回占位符 */
export function formatDateTime(value: string | null | undefined, fallback = '—'): string {
  const d = toDate(value)
  if (!d) return fallback

  const pad = (n: number) => String(n).padStart(2, '0')
  return (
    `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ` +
    `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`
  )
}

/**
 * 判断账号当前是否处于锁定期。
 *
 * 以「锁定到期时间是否仍在未来」为准，而不是看某个布尔标志：
 * 后端存的是到期时刻，锁定会自然过期，前端跟着这个语义走就不会
 * 出现「后端已解锁、界面仍显示锁着」的错位。
 */
export function isLocked(lockedUntil: string | null | undefined): boolean {
  const d = toDate(lockedUntil)
  return d !== null && d.getTime() > Date.now()
}

/**
 * 生成一个符合后端强度要求的随机初始密码。
 *
 * 用途：管理员新建账号时要手填初始密码。让人自己想一个的结果通常是
 * 「Aa123456」这类在字典里的组合，因此提供一个显式入口引导使用随机值。
 *
 * 字符集刻意去掉易混淆的 0/O/1/l/I：这些密码会被管理员念给同事或
 * 抄写在纸上，混淆字符会直接变成一次「密码错误」的登录失败——
 * 甚至可能触发账号锁定。
 */
export function generatePassword(length = 14): string {
  const lower = 'abcdefghijkmnpqrstuvwxyz'
  const upper = 'ABCDEFGHJKLMNPQRSTUVWXYZ'
  const digits = '23456789'
  const symbols = '!@#$%^&*'
  const all = lower + upper + digits + symbols

  const pick = (pool: string) => {
    const buf = new Uint32Array(1)
    crypto.getRandomValues(buf)
    return pool[buf[0] % pool.length]
  }

  // 先各取一个，保证四类字符都出现（后端与前端都按「长度 + 复杂度」评估强度）
  const chars = [pick(lower), pick(upper), pick(digits), pick(symbols)]
  while (chars.length < length) chars.push(pick(all))

  // Fisher–Yates 洗牌：不洗的话前四位永远是「小写 大写 数字 符号」，
  // 反而让规律变得可预测
  for (let i = chars.length - 1; i > 0; i--) {
    const buf = new Uint32Array(1)
    crypto.getRandomValues(buf)
    const j = buf[0] % (i + 1)
    ;[chars[i], chars[j]] = [chars[j], chars[i]]
  }

  return chars.join('')
}
