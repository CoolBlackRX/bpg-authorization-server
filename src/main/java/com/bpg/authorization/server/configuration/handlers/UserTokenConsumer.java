package com.bpg.authorization.server.configuration.handlers;

/**
 * 三个参数消费函数
 *
 * @param <T>
 * @param <H>
 * @param <C>
 * @param <R>
 */
@FunctionalInterface
public interface UserTokenConsumer<T, H, C, R> {
    R apply(T t, H h, C c);
}