package com.globalside.codingchallenge.rbac.constants;

public class SecuriryConstants {

    public static final String USER_NAME = "user";
    public static final String USER_PASSWORD = "user";
    public static final String USER_ROLE = "USER";

    public static final String ADMIN_NAME = "admin";
    public static final String ADMIN_PASSWORD = "admin";
    public static final String ADMIN_ROLE = "ADMIN";

    public static final String HAS_ROLE_ADMIN = "hasRole('" + ADMIN_ROLE + "')";
    public static final String HAS_ANY_ROLE = "hasAnyRole('" + USER_ROLE + "', '" + ADMIN_ROLE + "')";
}
