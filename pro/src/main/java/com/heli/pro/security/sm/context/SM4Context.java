package com.heli.pro.security.sm.context;

/**
 * @Author: YourName
 * @Date: 2021/5/11
 */
public class SM4Context {
    public int mode;

    public long[] sk;

    public boolean isPadding;

    public SM4Context() {
        this.mode = 1;
        this.isPadding = true;
        this.sk = new long[32];
    }
}
