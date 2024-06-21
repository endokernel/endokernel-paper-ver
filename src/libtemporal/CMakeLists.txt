cmake_minimum_required(VERSION 3.10)

project(libtemporal C ASM)

add_library(temporal SHARED
	"temporal.c"
    "small.c"
)

target_include_directories(temporal PUBLIC .)
target_include_directories(temporal PUBLIC ../libiso)
target_include_directories(temporal PUBLIC ../libintravirt)
set_property(TARGET temporal PROPERTY C_STANDARD 11)

install(TARGETS temporal DESTINATION lib)
install(FILES temporal.h DESTINATION include/temporal)

add_executable(temporal_test "test/main.c")
target_link_libraries(temporal_test temporal)
add_executable(temporal_baseline "test/baseline.c")
add_executable(temporal_syscall "test/syscall_policy.c")
target_link_libraries(temporal_syscall temporal)


add_executable(temporal_bench "test/benchmark_main.c")
target_compile_options(temporal_bench PRIVATE -g)
target_compile_definitions(temporal_bench PRIVATE -DHAS_TEMPORAL=1)
target_link_libraries(temporal_bench temporal)

add_executable(empty_bench "test/benchmark_main.c")
#target_compile_options(temporal_bench PRIVATE -g)
target_link_libraries(empty_bench temporal)

target_include_directories(temporal_test PUBLIC .)
target_include_directories(temporal_test PUBLIC ./test)
target_include_directories(temporal_test PUBLIC ../libiso)
target_include_directories(temporal_syscall PUBLIC .)
target_include_directories(temporal_syscall PUBLIC ./test)
target_include_directories(temporal_syscall PUBLIC ../libiso)
install(TARGETS temporal_test DESTINATION bin)
install(TARGETS temporal_syscall DESTINATION bin)
install(TARGETS temporal_bench DESTINATION bin)
install(TARGETS empty_bench DESTINATION bin)
