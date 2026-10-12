/**
 * 查询串拼装。
 *
 * 抽成独立模块而不是在每个 api 文件里各写一份：列表接口的查询参数只会
 * 越来越多（P3 的评估、P4 的整改都会再来几个），多份实现必然漂移成
 * 「这个文件跳过了空串、那个文件没有」——表现是同一个筛选条件在某个页面
 * 生效、在另一个页面被静默忽略，而这类缺陷不会报错。
 */

/**
 * 把查询对象拼成 query string，跳过「未设置」的值。
 *
 * @param query 具名 interface 或普通对象均可
 * @returns 形如 `?a=1&b=2`；没有任何有效参数时返回空串
 *
 * 判定为「未设置」的口径只有 `undefined` / `null` / 空串三种，
 * **刻意不含 `0` 与 `false`**：它们是合法取值（`include_children=false`
 * 与 `importance=0` 这种非法值也该原样送到后端去报错，而不是被前端
 * 悄悄丢掉然后返回一个「看起来没问题」的全量列表）。
 *
 * 参数类型写成 `object` 而不是 `Record<string, unknown>`：后者会拒收具名
 * interface —— TypeScript 只给匿名对象类型和类型别名隐式索引签名，
 * interface 没有。用 `object` + `Object.entries` 反而更省事，
 * 也不必让每个查询接口都去实现一个索引签名。
 */
export function toQueryString(query: object): string {
  const params = new URLSearchParams()
  for (const [key, value] of Object.entries(query)) {
    if (value === undefined || value === null || value === '') continue
    params.set(key, String(value))
  }
  const s = params.toString()
  return s ? `?${s}` : ''
}
