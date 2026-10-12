-- 000003_user_token_epoch 回滚
ALTER TABLE `users` DROP COLUMN `token_not_before`;
