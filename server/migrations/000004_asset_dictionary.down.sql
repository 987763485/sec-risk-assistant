-- 000004_asset_dictionary 回滚
--
-- 按外键依赖的逆序删除：assets 与 asset_groups 互相独立但 assets 指向
-- asset_groups（fk_assets_group），asset_groups 还有自引用外键
-- （fk_asset_groups_parent）。因此顺序必须是：
--   assets → asset_groups → dictionaries
-- 若先删 asset_groups，MySQL 会因为 assets 仍持有外键而拒绝。

DROP TABLE IF EXISTS `assets`;
DROP TABLE IF EXISTS `asset_groups`;
DROP TABLE IF EXISTS `dictionaries`;
