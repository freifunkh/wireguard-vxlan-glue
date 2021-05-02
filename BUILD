load("@rules_python//python:defs.bzl", "py_binary", "py_test")
load("@pip//:requirements.bzl", "requirement")


py_library(
    name = "netlink",
    srcs = ["netlink.py"],
    visibility = ["//visibility:public"],
    deps = [
       requirement("NetLink"),
       requirement("pyroute2")
    ],
)


py_test(
    name = "netlink_test",
    srcs = ["netlink_test.py"],
    deps = [
       ":netlink",
       requirement("mock"),
    ],
)
