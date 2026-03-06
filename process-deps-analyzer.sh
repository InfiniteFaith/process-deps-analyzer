#!/bin/bash

################################################################################
# 进程函数调用分析脚本 (Bash版本)
# 用于在Linux设备上直接运行
#
# 功能:
# 1. 分析实际调用的外部函数 (通过JMP_SLOT重定位)
# 2. 分析动态符号表中的外部引用
#
# 使用方法:
#   process-deps-analyzer.sh [进程名1] [进程名2] ...
################################################################################

# 配置 (默认进程列表，可通过命令行参数覆盖)
DEFAULT_PROCESSES=("ntpd")
PROCESSES=()
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
OUTPUT_DIR="./analysis_results_${TIMESTAMP}"

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# 检查必要工具
check_tools() {
    log_info "检查必要工具..."

    local tools=("readelf" "grep" "awk" "sort" "sed")
    local optional_tools=("nm" "ldd")
    local missing=()
    local missing_optional=()

    for tool in "${tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            missing+=("$tool")
        fi
    done

    for tool in "${optional_tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            missing_optional+=("$tool")
        fi
    done

    if [ ${#missing[@]} -gt 0 ]; then
        log_error "缺少必要工具: ${missing[*]}"
        return 1
    fi

    if [ ${#missing_optional[@]} -gt 0 ]; then
        log_warn "缺少可选工具 (符号查找功能将受限): ${missing_optional[*]}"
    fi

    log_info "所有必要工具已就绪"
    return 0
}

# 创建输出目录
create_output_dir() {
    mkdir -p "$OUTPUT_DIR"
    log_info "创建输出目录: $OUTPUT_DIR"
}

# 获取进程所有PID（支持多实例）
get_all_pids() {
    local proc_name=$1
    local pids=""

    # 尝试pidof (返回所有PID)
    pids=$(pidof "$proc_name" 2>/dev/null | tr ' ' '\n' | sort -n | tr '\n' ' ')

    # 如果失败，尝试ps
    if [ -z "$pids" ]; then
        pids=$(ps aux | grep -v grep | grep "$proc_name" | awk '{print $2}' | sort -n | tr '\n' ' ')
    fi

    echo "$pids"
}

# 获取进程PID（保持向后兼容，返回第一个）
get_pid() {
    local pids=$(get_all_pids "$1")
    echo "$pids" | awk '{print $1}'
}

# 分析调用的外部函数 (通过动态符号表)
analyze_functions_called() {
    local proc_name=$1
    local pid=$2
    local binary_path
    local output_file="$OUTPUT_DIR/${proc_name}_functions_called.csv"

    log_info "分析 ${proc_name} 调用的外部函数..."

    # 获取二进制路径
    binary_path=$(readlink -f "/proc/${pid}/exe")

    if [ ! -f "$binary_path" ]; then
        log_error "无法访问二进制文件: ${binary_path}"
        return 1
    fi

    log_info "二进制文件: ${binary_path}"

    # 写入CSV头
    echo "process_name,library_soname,function_name,offset,relocation_type" > "$output_file"

    # 首先尝试使用 JUMP_SLOT 重定位
    local has_relocations=0
    readelf -r "$binary_path" 2>/dev/null | grep -q JUMP_SLO && has_relocations=1

    if [ $has_relocations -eq 1 ]; then
        # 分析JMP_SLOT重定位
        readelf -r --wide "$binary_path" 2>/dev/null | grep JUMP_SLO | awk '{
            offset = $1
            func_name = ""
            # 从后往前找函数名
            for(i=NF; i>=1; i--) {
                if ($i !~ /^[0-9a-fA-F]+$/ && $i !~ /^R_/ && $i != "+" && $i != "0" && $i != "") {
                    func_name = $i
                    break
                }
            }
            if (func_name != "") {
                # 移除@VERSION后缀
                gsub(/@.*/, "", func_name)
                print "'"${proc_name}"'" ",unknown," func_name "," offset ",JMP_SLOT"
            }
        }' >> "$output_file"

        local count=$(tail -n +2 "$output_file" | wc -l)
        log_info "找到 ${count} 个调用的外部函数 (JMP_SLOT) -> ${output_file}"
    else
        # 没有JUMP_SLOT，使用动态符号表中的UND符号
        log_info "未找到JUMP_SLOT重定位，使用动态符号表分析..."
        readelf -s --wide "$binary_path" 2>/dev/null | grep 'GLOBAL.*UND.*FUNC' | awk '{
            value = $2
            sym_name = ""
            # 提取符号名 (从第8列开始到最后)
            for(i=8; i<=NF; i++) {
                if (sym_name == "") {
                    sym_name = $i
                } else {
                    sym_name = sym_name " " $i
                }
            }
            # 移除@VERSION后缀
            gsub(/@.*/, "", sym_name)
            if (sym_name != "") {
                print "'"${proc_name}"'" ",unknown," sym_name "," value ",DYN_SYM"
            }
        }' >> "$output_file"

        local count=$(tail -n +2 "$output_file" | wc -l)
        log_info "找到 ${count} 个调用的外部函数 (动态符号表) -> ${output_file}"
    fi
}

# 全局变量：进程的依赖库列表
PROCESS_LIBS=""

# 全局变量：符号缓存 (格式: "symbol_name:library_name")
SYMBOL_CACHE=""

# 构建符号缓存（性能优化关键）
# 一次性提取所有依赖库的符号表，避免每个符号都运行nm
build_symbol_cache() {
    if ! command -v nm &> /dev/null; then
        log_warn "nm 不可用，无法构建符号缓存"
        return 1
    fi

    if [ -z "$PROCESS_LIBS" ]; then
        return 1
    fi

    log_info "构建符号缓存 (正在提取所有依赖库的符号表)..."

    local cache_file="$OUTPUT_DIR/.symbol_cache.tmp"
    > "$cache_file"

    for lib_path in $PROCESS_LIBS; do
        if [ -f "$lib_path" ]; then
            local lib_name=$(basename "$lib_path")
            # 提取所有导出的函数符号 (T = 代码段中的全局符号)
            nm -D "$lib_path" 2>/dev/null | grep ' T ' | awk -v lib="$lib_name" '{
                # 提取最后一列作为符号名（兼容多种nm输出格式）
                # nm输出格式通常是: address type name 或 name@@@VERSION address type
                # 使用 $NF（最后一列）作为符号名更可靠
                symbol = $NF
                # 移除@VERSION后缀
                gsub(/@.*/, "", symbol)
                print symbol ":" lib
            }' >> "$cache_file"
        fi
    done

    # 加载到内存（每行一个 symbol:lib 条目）
    SYMBOL_CACHE=$(cat "$cache_file" | sort -u)
    rm -f "$cache_file"

    local cache_size=$(echo "$SYMBOL_CACHE" | wc -l)
    log_info "符号缓存构建完成: ${cache_size} 个符号已缓存"
    return 0
}

# 初始化进程的依赖库列表
init_process_libs() {
    local pid=$1
    local binary_path=$(readlink -f "/proc/${pid}/exe")

    if [ -f "$binary_path" ]; then
        # 从ldd获取依赖库列表，只保留.so文件路径
        PROCESS_LIBS=$(ldd "$binary_path" 2>/dev/null | grep '\.so' | grep -v 'not found' | awk '{for(i=1;i<=NF;i++) if($i ~/\/.*\.so/) {print $i; break}}' | sort -u)
        echo "[初始化] 已加载 $(echo "$PROCESS_LIBS" | wc -w) 个依赖库" >&2
    fi
}

# 查找符号在运行时库中的定义（使用缓存优化版本）
# 优先在进程依赖库中搜索，失败则在所有库中搜索
find_symbol_in_libraries() {
    local symbol_name=$1

    # 首先在缓存中查找（性能飞跃关键：避免每个符号都运行nm）
    if [ -n "$SYMBOL_CACHE" ]; then
        local cached_lib=$(echo "$SYMBOL_CACHE" | grep "^${symbol_name}:" | cut -d':' -f2 | head -1)
        if [ -n "$cached_lib" ]; then
            #echo "[缓存命中] $symbol_name -> $cached_lib" >&2
            echo "$cached_lib"
            return
        fi
    fi

    # 检查nm是否可用
    if ! command -v nm &> /dev/null; then
        echo ""
        return
    fi

    # 提取前缀并转为小写
    local prefix=""
    if [[ "$symbol_name" == *"_"* ]]; then
        # 有下划线，提取第一个'_'之前的部分
        prefix=$(echo "$symbol_name" | cut -d'_' -f1 | tr '[:upper:]' '[:lower:]')
    fi

    echo "[缓存未命中] $symbol_name (前缀: '${prefix}')" >&2

    # 如果前缀为空，直接在依赖库中用nm搜索定义的符号
    if [ -z "$prefix" ]; then
        return
        # if [ -n "$PROCESS_LIBS" ]; then
        #     echo "[nm搜索] 依赖库中查找符号定义..." >&2
        #     for lib_path in $PROCESS_LIBS; do
        #         if [ -f "$lib_path" ]; then
        #             # 使用 " T " 查找在代码段定义的全局符号
        #             if nm -D "$lib_path" 2>/dev/null | grep -q " T ${symbol_name}$"; then
        #                 local lib_name=$(basename "$lib_path")
        #                 echo "[找到] $symbol_name -> $lib_name" >&2
        #                 echo "$lib_name"
        #                 return
        #             fi
        #         fi
        #     done
        # fi
        # echo "[未找到] $symbol_name" >&2
        # echo ""
        # return
    fi

    # 前缀不为空，则在进程依赖库中搜索
    if [ -n "$PROCESS_LIBS" ]; then
        for lib_path in $PROCESS_LIBS; do
            if [ -f "$lib_path" ]; then
                local lib_name=$(basename "$lib_path")
                # 检查库名是否包含前缀
                if [[ "$lib_name" == *"${prefix}"* ]]; then
                    echo "[检查依赖库] $lib_name" >&2
                    # 使用 " T " 查找在代码段定义的全局符号
                    if nm -D "$lib_path" 2>/dev/null | grep -q " T ${symbol_name}$"; then
                        echo "[找到] $symbol_name -> $lib_name" >&2
                        echo "$lib_name"
                        return
                    fi
                fi
            fi
        done
    fi

    echo "[未找到] $symbol_name" >&2
    echo ""
}

# 更新CSV文件中的unknown库名
update_unknown_libraries() {
    local proc_name=$1
    local csv_file="$OUTPUT_DIR/${proc_name}_functions_called.csv"
    local temp_file="$OUTPUT_DIR/.temp_update.csv"

    if [ ! -f "$csv_file" ]; then
        return
    fi

    # 检查nm是否可用
    if ! command -v nm &> /dev/null; then
        log_warn "nm 不可用，跳过符号查找"
        return
    fi

    log_info "解析 ${proc_name} 的符号所属库..."

    # 写入CSV头
    head -1 "$csv_file" > "$temp_file"

    # 统计变量（使用文件在子shell间传递）
    local stats_file="$OUTPUT_DIR/.stats.tmp"
    echo "0 0" > "$stats_file"  # format: total found

    # 读取初始统计值
    local stats=($(cat "$stats_file"))
    local current_total=${stats[0]}

    # 处理每一行数据
    tail -n +2 "$csv_file" | while IFS=',' read -r process_name library_soname function_name offset relocation_type; do
        local found=${stats[1]}

        ((current_total++))

        # echo -e "${BLUE}[DEBUG] 读取行数据:${NC}" >&2
        # echo "  -> 进程名称 (process_name): $process_name" >&2
        # echo "  -> 库名称 (library_soname): $library_soname" >&2
        # echo "  -> 函数名称 (function_name): $function_name" >&2
        # echo "  -> 偏移地址 (offset): $offset"
        # echo "  -> 重定位类型 (relocation_type): $relocation_type" >&2

        if [ "$library_soname" = "unknown" ]; then
            # 查找符号在哪个库中（保留日志用于调试）
            #echo "[${current_total}/${stats[0]}] 查找符号: $function_name" >&2

            found_lib=$(find_symbol_in_libraries "$function_name")
            if [ -n "$found_lib" ]; then
                library_soname="$found_lib"
                ((found++))
                #echo "[${current_total}/${stats[0]}] ✓ 找到: $function_name -> $found_lib" >&2
            #else
                #echo "[${current_total}/${stats[0]}] ✗ 未找到: $function_name" >&2
            fi
        fi

        echo "${process_name},${library_soname},${function_name},${offset},${relocation_type}"
        echo "$current_total $found" > "$stats_file"
    done >> "$temp_file"

    # 读取统计
    local stats=($(cat "$stats_file"))
    local total=${stats[0]}
    local found=${stats[1]}
    rm -f "$stats_file"

    # 替换原文件
    mv "$temp_file" "$csv_file"

    log_info "符号解析完成: ${found}/${total} 个符号已解析"
}

# 分析动态符号表中的外部引用
analyze_dynamic_symbols() {
    local proc_name=$1
    local pid=$2
    local binary_path
    local output_file="$OUTPUT_DIR/${proc_name}_dynamic_symbols.csv"

    log_info "分析 ${proc_name} 的动态符号表..."

    binary_path=$(readlink -f "/proc/${pid}/exe")

    if [ ! -f "$binary_path" ]; then
        log_error "无法访问二进制文件: ${binary_path}"
        return 1
    fi

    # 写入CSV头 (增加library_soname列)
    echo "process_name,symbol_name,symbol_type,symbol_binding,value,library_soname" > "$output_file"

    # 分析动态符号表
    # readelf -s 输出格式: Num Value Size Type Bind Vis Ndx Name
    # 第5列是GLOBAL(绑定), 第7列是UND(未定义), 需要匹配GLOBAL.*UND
    readelf -s --wide "$binary_path" 2>/dev/null | grep 'GLOBAL.*UND' | awk '{
        value = $2
        type_name = $4
        bind = $5
        ndx = $7
        sym_name = ""

        # 提取符号名 (从第8列开始到最后)
        for(i=8; i<=NF; i++) {
            if (sym_name == "") {
                sym_name = $i
            } else {
                sym_name = sym_name " " $i
            }
        }

        if (ndx == "UND") {
            print "'"${proc_name}"'" "," sym_name "," type_name "," bind "," value ",unknown"
        }
    }' >> "$output_file"

    local count=$(tail -n +2 "$output_file" | wc -l)
    log_info "找到 ${count} 个外部符号引用 -> ${output_file}"
}

# 更新动态符号表中的unknown库名
update_dynamic_symbols_unknown() {
    local proc_name=$1
    local csv_file="$OUTPUT_DIR/${proc_name}_dynamic_symbols.csv"
    local temp_file="$OUTPUT_DIR/.temp_dyn_sym_update.csv"

    if [ ! -f "$csv_file" ]; then
        return
    fi

    # 检查nm是否可用
    if ! command -v nm &> /dev/null; then
        log_warn "nm 不可用，跳过符号查找"
        return
    fi

    log_info "解析 ${proc_name} 动态符号所属库..."

    # 写入CSV头
    head -1 "$csv_file" > "$temp_file"

    # 统计变量（使用文件在子shell间传递）
    local stats_file="$OUTPUT_DIR/.stats_dyn.tmp"
    echo "0 0" > "$stats_file"  # format: total found

    # 读取初始统计值
    local stats=($(cat "$stats_file"))
    local current_total=${stats[0]}

    # 处理每一行数据
    tail -n +2 "$csv_file" | while IFS=',' read -r process_name symbol_name symbol_type symbol_binding value library_soname _; do
        local found=${stats[1]}
        # echo -e "${BLUE}[DEBUG] 读取行数据:${NC}" >&2
        # echo "  -> 进程名称 (process_name): $process_name" >&2
        # echo "  -> 库名称 (library_soname): $library_soname" >&2
        # echo "  -> 函数名称 (symbol_name): $symbol_name" >&2
        ((current_total++))

        if [ "$library_soname" = "unknown" ]; then
            # 从符号名中移除@VERSION后缀
            clean_symbol=$(echo "$symbol_name" | awk '{print $1}' | cut -d'@' -f1)
            # 查找符号在哪个库中（保留日志用于调试）
            #echo "[${current_total}/${stats[0]}] 查找符号: $clean_symbol" >&2
            found_lib=$(find_symbol_in_libraries "$clean_symbol")
            if [ -n "$found_lib" ]; then
                library_soname="$found_lib"
                ((found++))
                #echo "[${current_total}/${stats[0]}] ✓ 找到: $clean_symbol -> $found_lib" >&2
            #else
                #echo "[${current_total}/${stats[0]}] ✗ 未找到: $clean_symbol" >&2
            fi
        fi

        echo "${process_name},${symbol_name},${symbol_type},${symbol_binding},${value},${library_soname}"
        echo "$current_total $found" > "$stats_file"
    done >> "$temp_file"

    # 读取统计
    local stats=($(cat "$stats_file"))
    local total=${stats[0]}
    local found=${stats[1]}
    rm -f "$stats_file"

    # 替换原文件
    mv "$temp_file" "$csv_file"

    log_info "符号解析完成: ${found}/${total} 个符号已解析"
}

# 分析单个进程（支持多实例）
analyze_process() {
    local proc_name=$1
    local pids

    echo ""
    echo "================================================================================"
    echo "分析进程: ${proc_name}"
    echo "================================================================================"

    # 获取所有PID
    pids=$(get_all_pids "$proc_name")

    if [ -z "$pids" ]; then
        log_error "未找到进程: ${proc_name}"
        return 1
    fi

    # 转换为数组
    local pid_array=($pids)
    local pid_count=${#pid_array[@]}

    log_info "找到 ${pid_count} 个 ${proc_name} 进程实例: ${pids}"

    # 分析每个实例
    for pid in "${pid_array[@]}"; do
        log_info "分析 ${proc_name} 实例, PID: ${pid}"

        # 检查进程可访问性
        if [ ! -d "/proc/${pid}" ]; then
            log_error "无法访问 /proc/${pid}"
            continue
        fi

        # 使用带PID后缀的输出文件名以区分多实例
        local proc_suffix="${proc_name}_pid${pid}"

        # 初始化进程依赖库列表
        init_process_libs "$pid"

        # 构建符号缓存（性能优化关键：一次性提取所有符号）
        build_symbol_cache

        # 运行各项分析
        analyze_functions_called "$proc_suffix" "$pid"
        analyze_dynamic_symbols "$proc_suffix" "$pid"

        # 更新unknown库名 (通过符号查找)
        echo ""
        log_info "查找符号定义位置..."
        update_unknown_libraries "$proc_suffix"
        update_dynamic_symbols_unknown "$proc_suffix"
    done

    return 0
}

# 生成汇总报告
generate_summary() {
    local summary_file="$OUTPUT_DIR/analysis_summary.txt"

    log_info "生成汇总报告..."

    cat > "$summary_file" << EOF
进程函数调用分析报告
========================================

分析时间: $(date)
分析目录: $OUTPUT_DIR

分析进程:
EOF

    for proc in "${PROCESSES[@]}"; do
        echo "  - ${proc}" >> "$summary_file"
    done

    echo "" >> "$summary_file"
    echo "========================================" >> "$summary_file"
    echo "分析结果:" >> "$summary_file"
    echo "" >> "$summary_file"

    # 列出所有匹配的分析文件（支持多实例命名）
    for csv_file in "$OUTPUT_DIR"/*_functions_called.csv; do
        if [ -f "$csv_file" ]; then
            local basename=$(basename "$csv_file")
            # 移除后缀获取进程标识
            local proc_id="${basename%_functions_called.csv}"
            echo "--- ${proc_id} ---" >> "$summary_file"

            # 调用的函数
            if [ -f "$OUTPUT_DIR/${proc_id}_functions_called.csv" ]; then
                local count=$(tail -n +2 "$OUTPUT_DIR/${proc_id}_functions_called.csv" | wc -l)
                echo "  调用的外部函数: ${count} 个" >> "$summary_file"
            fi

            # 动态符号
            if [ -f "$OUTPUT_DIR/${proc_id}_dynamic_symbols.csv" ]; then
                local count=$(tail -n +2 "$OUTPUT_DIR/${proc_id}_dynamic_symbols.csv" | wc -l)
                echo "  外部符号引用: ${count} 个" >> "$summary_file"
            fi

            echo "" >> "$summary_file"
        fi
    done

    cat "$summary_file"
}

# 主函数
main() {
    echo "================================================================================"
    echo "进程库依赖和函数调用分析工具"
    echo "================================================================================"
    echo ""

    # 解析命令行参数
    if [ $# -gt 0 ]; then
        # 使用命令行传入的进程列表
        PROCESSES=("$@")
        log_info "使用命令行指定的进程: ${PROCESSES[*]}"
    else
        # 使用默认进程列表
        PROCESSES=("${DEFAULT_PROCESSES[@]}")
        log_info "使用默认进程列表: ${PROCESSES[*]}"
    fi

    # 检查工具
    check_tools || exit 1

    # 创建输出目录
    create_output_dir

    # 分析每个进程
    for proc in "${PROCESSES[@]}"; do
        analyze_process "$proc"
    done

    # 生成汇总报告
    echo ""
    generate_summary

    log_info "分析完成! 结果保存在: ${OUTPUT_DIR}"
}

# 运行主函数 (传入所有命令行参数)
main "$@"
