CREATE DATABASE ctf CHARACTER SET utf8mb4 COLLATE = utf8mb4_unicode_ci;

use ctf;

CREATE TABLE `messages` (
    `id` INT NOT NULL PRIMARY KEY AUTO_INCREMENT,
    `uid` INT NOT NULL,
    `message` TEXT NOT NULL
);

CREATE TABLE `users` (
    `id` INT NOT NULL PRIMARY KEY AUTO_INCREMENT,
    `name` VARCHAR(32) NOT NULL UNIQUE,
    `password` VARCHAR(64) NOT NULL,
    `admin` INT NOT NULL
);

INSERT INTO
    `users` (`id`, `name`, `password`, `admin`)
VALUES
    (1, 'admin', '<uuid>', 1);