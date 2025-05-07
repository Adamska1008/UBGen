# 声明库并设置 C++17
add_library(RuleActionCallbackLib RuleActionCallback.cpp)
target_compile_features(RuleActionCallbackLib PUBLIC cxx_std_17)

# 公共 include 路径
target_include_directories(RuleActionCallbackLib PUBLIC
    ${CLANG_INCLUDE_DIRS}
    ${LLVM_INCLUDE_DIRS}
    ${CMAKE_CURRENT_SOURCE_DIR}
)

# 公共编译选项：MSVC vs GCC/Clang
target_compile_options(RuleActionCallbackLib PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:/W4;/WX>
    $<$<OR:$<CXX_COMPILER_ID:GNU>,$<CXX_COMPILER_ID:Clang>>:
        -Wall;-Wextra;-Wpedantic;-Werror;-fdiagnostics-color=always
    >
    # 仅非 MSVC 平台启用本机架构优化
    $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-march=native>
)

# 链接逻辑：动态 vs 静态
if(CLANG_LINK_CLANG_DYLIB)
    target_link_libraries(RuleActionCallbackLib PUBLIC
        LLVM
    )
    clang_target_link_libraries(RuleActionCallbackLib PUBLIC)
else()
    # 每次都用新的变量，防止累积
    llvm_map_components_to_libnames(LLVM_LIBS_RULE_ACTION support core)
    target_link_libraries(RuleActionCallbackLib PUBLIC
        ${LLVM_LIBS_RULE_ACTION}
        clangASTMatchers
        clangTransformer
        clangTooling
    )
endif()


# —— 对其他库同理 —— #

function(configure_lib libname srcfile)
    add_library(${libname} ${srcfile})
    target_compile_features(${libname} PUBLIC cxx_std_17)
    target_include_directories(${libname} PUBLIC
        ${CLANG_INCLUDE_DIRS}
        ${LLVM_INCLUDE_DIRS}
        ${CMAKE_CURRENT_SOURCE_DIR}
    )
    target_compile_options(${libname} PRIVATE
        $<$<CXX_COMPILER_ID:MSVC>:/W4;/WX>
        $<$<OR:$<CXX_COMPILER_ID:GNU>,$<CXX_COMPILER_ID:Clang>>:
            -Wall;-Wextra;-Wpedantic;-Werror
        >
        $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-march=native>
    )
    target_link_libraries(${libname} PUBLIC RuleActionCallbackLib)

    if(CLANG_LINK_CLANG_DYLIB)
        target_link_libraries(${libname} PUBLIC LLVM)
        clang_target_link_libraries(${libname} PUBLIC)
    else()
        # 每个库都用独立变量名
        llvm_map_components_to_libnames(LLVM_LIBS_${libname} support core)
        target_link_libraries(${libname} PUBLIC
            ${LLVM_LIBS_${libname}}
            clangASTMatchers
            clangTransformer
            clangTooling
        )
    endif()
endfunction()

# 调用上面函数生成各个库
configure_lib(AnalyzerInstrumenterLib AnalyzerInstrumenter.cpp)
configure_lib(AddBracesLib         AddBraces.cpp)
configure_lib(ArrayIndexAddLib     ArrayIndexAdd.cpp)
configure_lib(StackToHeapLib       StackToHeap.cpp)
configure_lib(IntegerAddLib        IntegerAdd.cpp)

# 子目录
add_subdirectory(tool)
