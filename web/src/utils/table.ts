/**
 * el-table 作用域插槽的类型收敛。
 *
 * Element Plus 把 `#default="{ row }"` 的 row 放宽成 `Record<PropertyKey, any>`
 * —— 它没有把组件的泛型参数透传到插槽上，`<!-- @vue-generic -->` 也救不了。
 * 而「带索引签名的对象」在 TypeScript 里**不能**赋给具名 interface
 * （隐式索引签名只给匿名类型，不给 interface），所以不能直接把 row 传给
 * 需要具体类型的函数。
 *
 * 这里用收敛函数而不是在模板里写 `row as Asset`：
 * 模板中的断言写错了不会有任何提示，而函数签名本身受类型检查，
 * 而且「哪里做了类型收敛」在代码里是可搜索的。
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any -- 复刻 Element Plus 未导出的 DefaultRow 定义；换成 unknown 会让模板里对 row 的属性访问全部报错
export type TableRow = Record<PropertyKey, any>

/** 把插槽给出的 row 收敛成期望的行类型。仅在 `#default="{ row }"` 内使用。 */
export function asRow<T>(row: TableRow): T {
  return row as unknown as T
}
