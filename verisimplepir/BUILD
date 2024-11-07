# Core library


cc_library(
    name = "verisimplepir_lib",
    srcs = glob([
        "src/lib/**/*.cpp",
        "src/lib/**/*.cc",
    ]),
    hdrs = glob([
        "src/lib/**/*.h",
        "src/lib/**/*.hpp",
    ]),
    copts = [
        "-std=c++17",
        "-fPIC",
        "-O3",
        "-maes",
        "-msse4",
        "-Wall",
        "-fno-omit-frame-pointer",
        "-Wno-ignored-attributes",
    ],
    includes = [
        "src/lib",
        "test",
    ],
    linkopts = [
        "-lssl",
        "-lcrypto",
        "-lgsl",
        "-lgslcblas",
        "-lrt",
        "-L/usr/lib/x86_64-linux-gnu",
        "-L/usr/local/lib",
        "-Wl,--export-dynamic,-z,defs",
    ],
    visibility = ["//visibility:public"],
)

# Basic test binary
cc_binary(
    name = "pir_test",
    srcs = ["src/demo/test/pir_test.cpp"],
    deps = [":verisimplepir_lib"],
)

# Benchmark binaries
cc_binary(
    name = "preproc_pir_bench",
    srcs = ["src/demo/bench/preproc_pir_bench.cpp"],
    deps = [":verisimplepir_lib"],
)

cc_binary(
    name = "pir_bench",
    srcs = ["src/demo/bench/pir_bench.cpp"],
    deps = [":verisimplepir_lib"],
)

cc_binary(
    name = "simplepir_bench",
    srcs = ["src/demo/bench/simplepir_bench.cpp"],
    deps = [":verisimplepir_lib"],
)

# Parameter generation script
cc_binary(
    name = "params",
    srcs = ["src/demo/scripts/params.cpp"],
    deps = [":verisimplepir_lib"],
)