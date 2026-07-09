#!/bin/bash

Red="\033[31m"
Green="\033[32m"
Yellow="\033[33m"
Blue="\033[34m"
Nc="\033[0m"
Red_globa="\033[41;37m"
Green_globa="\033[42;37m"
Yellow_globa="\033[43;37m"
Blue_globa="\033[44;37m"
Info="${Green}[信息]${Nc}"
Error="${Red}[错误]${Nc}"
Tip="${Yellow}[提示]${Nc}"

work_dir="/var/anyst"
anyst_bin="$work_dir/anyst"
config_path="$work_dir/config.yaml"
service_path="/lib/systemd/system/anyst.service"
raw_conf_path="$work_dir/rawconf"
version_file="$work_dir/version"
github_repo="bryet/anyst"

check_root(){
    if [ "$(id -u)" != "0" ]; then
        echo -e "${Error} 当前非ROOT账号(或没有ROOT权限)，无法继续操作，请更换ROOT账号或使用 ${Green_globa}sudo -i${Nc} 命令获取临时ROOT权限（执行后可能会提示输入当前账号的密码）。"
        exit 1
    fi
}

check_arch(){
    arch=$(uname -m)
    case "$arch" in
        x86_64|x64|amd64)
            arch="x86_64"
            ;;
        aarch64|arm64|armv8*)
            arch="aarch64"
            ;;
        *)
            echo -e "${Error} 检测到您的架构不支持: $arch"
            exit 1
            ;;
    esac
    echo -e "${Info} 检测到架构: ${Green}$arch${Nc}"
}

check_musl(){
    if ldd --version 2>&1 | grep -q "musl"; then
        musl="musl"
    else
        musl="gnu"
    fi
}

check_release(){
    if [[ -e /etc/os-release ]]; then
        . /etc/os-release
        release=$ID
    elif [[ -e /usr/lib/os-release ]]; then
        . /usr/lib/os-release
        release=$ID
    fi
    os_version=$(echo $VERSION_ID | cut -d. -f1,2 2>/dev/null)

    if [[ "${release}" == "ol" ]]; then
        release=oracle
    elif [[ ! "${release}" =~ ^(kali|centos|ubuntu|fedora|debian|almalinux|rocky|alpine|oracle|arch|manjaro|opensuse-tumbleweed)$ ]]; then
        echo -e "${Error} 抱歉，此脚本不支持您的操作系统: $release"
        echo -e "${Info} 支持的系统: Ubuntu, Debian, CentOS, Fedora, Kali, AlmaLinux, Rocky, Oracle, Alpine, Arch, Manjaro, OpenSUSE"
        exit 1
    fi
}

check_pmc(){
    check_release
    case "$release" in
        debian|ubuntu|kali)
            updates="apt update -y"
            installs="apt install -y"
            apps=("wget" "curl" "tar" "openssl")
            ;;
        almalinux|centos|rocky|oracle|fedora)
            updates="dnf update -y"
            installs="dnf install -y"
            apps=("wget" "curl" "tar" "openssl")
            ;;
        opensuse-tumbleweed)
            updates="zypper refresh"
            installs="zypper install -y"
            apps=("wget" "curl" "tar" "openssl")
            ;;
        arch|manjaro|parch)
            updates="pacman -Syu"
            installs="pacman -Syu --noconfirm"
            apps=("wget" "curl" "tar" "openssl")
            ;;
        alpine)
            updates="apk update"
            installs="apk add"
            apps=("wget" "curl" "tar" "openssl")
            ;;
        *)
            echo -e "${Error} 不支持的发行版: $release"
            exit 1
            ;;
    esac
}

install_base(){
    check_pmc
    cmds=("wget" "curl" "tar" "openssl")
    echo -e "${Info} 你的系统是 ${Red}$release $os_version${Nc}"
    echo

    for i in "${!cmds[@]}"; do
        if ! command -v "${cmds[i]}" &>/dev/null; then
            DEPS+=("${apps[i]}")
        fi
    done

    if [ ${#DEPS[@]} -gt 0 ]; then
        echo -e "${Tip} 安装依赖列表：${Green}${DEPS[*]}${Nc} 请稍后..."
        $updates
        $installs "${DEPS[@]}"
    else
        echo -e "${Info} 所有依赖已存在，不需要额外安装。"
    fi
}

check_new_ver(){
    new_ver=$(curl -Ls "https://api.github.com/repos/${github_repo}/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
    if [[ -z ${new_ver} ]]; then
        echo -e "${Error} anyst 最新版本获取失败，请手动输入版本号"
        echo
        read -e -p "请输入版本号:" new_ver
    else
        echo -e "${Info} anyst 目前最新版本为 ${Green}${new_ver}${Nc}"
    fi
}

check_installed_ver(){
    if [ -f "$version_file" ]; then
        installed_ver=$(cat "$version_file")
        echo -e "${Info} 当前安装的 anyst 版本: ${Green}${installed_ver}${Nc}"
    else
        installed_ver="未安装"
    fi
}

download_anyst(){
    local ver=$1
    local tarball="anyst-${arch}-unknown-linux-${musl}.tar.gz"

    if [[ -z ${ver} ]]; then
        ver="$new_ver"
        echo -e "${Tip} 若为国内机器建议使用大陆镜像加速下载"
        read -e -p "是否使用？[y/N]:" use_mirror
        [[ -z ${use_mirror} ]] && use_mirror="n"
        if [[ ${use_mirror} == [Yy] ]]; then
            dl_url="https://gh-proxy.org/github.com/${github_repo}/releases/download/${ver}/anyst-${arch}-unknown-linux-${musl}-${ver}.tar.gz"
        else
            dl_url="https://github.com/${github_repo}/releases/download/${ver}/anyst-${arch}-unknown-linux-${musl}-${ver}.tar.gz"
        fi
    else
        dl_url="https://gh-proxy.org/github.com/${github_repo}/releases/download/${ver}/anyst-${arch}-unknown-linux-${musl}-${ver}.tar.gz"
    fi

    echo -e "${Info} 正在从 ${Blue}${dl_url}${Nc} 下载 anyst..."
    mkdir -p "$work_dir"
    cd "$work_dir"
    if ! wget --no-check-certificate -q --show-progress "$dl_url" -O "$tarball"; then
        echo -e "${Error} 下载失败，请检查网络或版本号"
        rm -f "$tarball"
        exit 1
    fi
    tar -xzf "$tarball"
    rm -f "$tarball"
    echo "$ver" >"$version_file"
}

Install_anyst(){
    check_root

    if [ -f "$anyst_bin" ]; then
        echo -e "${Tip} anyst 已安装，无需安装"
        return
    fi

    install_base
    check_arch
    check_musl

    if [[ -n $1 ]]; then
        echo -e "${Tip} 即将安装 anyst ${Green}$1${Nc}"
    else
        check_new_ver
        echo -e "${Tip} 即将安装 anyst ${Green}${new_ver}${Nc}"
    fi
    
    download_anyst "$1"

    systemctl stop anyst 2>/dev/null

    chmod +x "$anyst_bin"

    if [ -f "$work_dir/anyst.service" ]; then
        cp -f "$work_dir/anyst.service" "$service_path"
    else
        echo -e "${Error} 找不到 anyst.service 模板文件"
        exit 1
    fi

    if [ ! -f "$config_path" ] && [ -f "$work_dir/config.example.yaml" ]; then
        cp -f "$work_dir/config.example.yaml" "$config_path"
    fi

    if [ ! -f "$raw_conf_path" ]; then
        touch "$raw_conf_path"
    fi

    systemctl daemon-reload
    systemctl enable anyst

    if [ -f "$anyst_bin" ] && [ -f "$service_path" ] && [ -f "$config_path" ]; then
        echo -e "${Info} anyst 安装成功！"
        openssl req -x509 -newkey rsa:4096 -nodes -keyout key.pem -out cert.pem -subj "/C=CN/ST=GD/L=SZ/O=Dev/OU=IT/CN=bing.com" -days 3650 &> /dev/null
        main_menu
    else
        echo -e "${Error} anyst 安装失败，请检查"
        exit 1
    fi
}

Update_anyst(){
    check_root
    check_arch
    check_musl

    if [ ! -f "$anyst_bin" ]; then
        echo -e "${Error} anyst 尚未安装，请先安装"
        return
    fi

    check_installed_ver
    check_new_ver

    if [ "$installed_ver" == "$new_ver" ]; then
        echo -e "${Info} 已经是最新版本${Green}${new_ver}${Nc}，无需更新"
        exit 1
    fi

    echo -e "${Tip} 即将更新 anyst: ${installed_ver} -> ${new_ver}"
    read -e -p "确认更新？[y/n]:" confirm
    [[ -z ${confirm} ]] && confirm="n"
    if [[ ${confirm} != [Yy] ]]; then
        echo -e "${Info} 已取消更新"
        return
    fi

    cp -f "$config_path" /tmp/config.yaml 2>/dev/null
    cp -f "$raw_conf_path" /tmp/rawconf 2>/dev/null

    download_anyst
    systemctl stop anyst 2>/dev/null
    chmod +x "$anyst_bin"

    cp -f /tmp/config.yaml "$config_path" 2>/dev/null
    cp -f /tmp/rawconf "$raw_conf_path" 2>/dev/null
    rm -f /tmp/config.yaml /tmp/rawconf

    systemctl start anyst 2>/dev/null

    echo -e "${Info} anyst 已更新至 ${new_ver}"
}

Uninstall_anyst(){
    check_root

    if [ ! -f "$anyst_bin" ]; then
        echo -e "${Error} anyst 尚未安装，无需卸载"
        return
    fi

    echo -e "${Yellow}================================${Nc}"
    echo -e "${Red}警告: 即将卸载 anyst!${Nc}"
    echo -e "${Yellow}================================${Nc}"
    read -e -p "确认卸载？[y/n]:" confirm
    [[ -z ${confirm} ]] && confirm="n"
    if [[ ${confirm} != [Yy] ]]; then
        echo -e "${Info} 已取消卸载"
        return
    fi

    systemctl stop anyst 2>/dev/null
    systemctl disable anyst 2>/dev/null
    rm -f "$anyst_bin"
    rm -f "$service_path"
    rm -rf "$work_dir"
    systemctl daemon-reload
    echo -e "${Info} anyst 已成功卸载"
}

Start_anyst(){
    check_root
    if [ ! -f "$service_path" ]; then
        echo -e "${Error} anyst 服务文件不存在，请先安装"
        return
    fi
    systemctl start anyst
    if systemctl is-active --quiet anyst; then
        echo -e "${Info} anyst 已启动"
    else
        echo -e "${Error} anyst 启动失败，请检查: systemctl status anyst"
    fi
}

Stop_anyst(){
    check_root
    systemctl stop anyst 2>/dev/null
    echo -e "${Info} anyst 已停止"
}

Restart_anyst(){
    check_root
    if [ ! -f "$service_path" ]; then
        echo -e "${Error} anyst 服务文件不存在，请先安装"
        return
    fi
    systemctl restart anyst
    if systemctl is-active --quiet anyst; then
        echo -e "${Info} anyst 已重启"
    fi
}

Status_anyst(){
    if systemctl is-active --quiet anyst 2>/dev/null; then
        echo -e "${Info} anyst 运行状态: ${Green}运行中${Nc}"
        systemctl status anyst --no-pager -l 2>/dev/null || true
    else
        echo -e "${Info} anyst 运行状态: ${Red}未运行${Nc}"
    fi
}

View_log(){
    local log_file="$work_dir/log_anyst.log"
    if [ -f "$log_file" ]; then
        echo -e "${Info} 按 ${Red}Ctrl+C${Nc} 退出日志查看"
        tail -f "$log_file"
    else
        echo -e "${Tip} 日志文件尚未生成，尝试查看 systemd 日志..."
        journalctl -u anyst -f --no-pager 2>/dev/null || echo -e "${Error} 暂无日志"
    fi
}

read_tunnel_mode(){
    echo -e "-----------------------------------"
    echo -e "请选择隧道模式: "
    echo -e "-----------------------------------"
    echo -e "[1] ${Green}加密转发${Nc} (客户端模式)"
    echo -e "    说明: 监听本地端口，通过TLS隧道转发到远程服务器"
    echo -e "    适用于: 国内中转机 -> 境外服务器"
    echo -e "-----------------------------------"
    echo -e "[2] ${Green}解密接收${Nc} (服务端模式)"
    echo -e "    说明: 接收TLS加密流量，解密后转发到目标地址"
    echo -e "    适用于: 境外服务器接收并解密 -> 转发到落地代理"
    echo -e "-----------------------------------"
    read -p "请选择 [1-2]: " tunnel_mode
    case "$tunnel_mode" in
        1) flag_mode="client" ;;
        2) flag_mode="server" ;;
        *) echo -e "${Error} 选择错误"; exit 1 ;;
    esac
}

read_listen(){
    echo -e "-----------------------------------"
    echo -e "请问你要将本机哪个端口接收到的流量进行转发?"
    read -p "请输入: " flag_port
    [[ -z ${flag_port} ]] && echo -e "${Error} 端口不能为空" && exit 1
    flag_listen="[::]:${flag_port}"
}

read_remote(){
    echo -e "-----------------------------------"
    echo -e "请问你要将本机从${Green}${flag_port}${Nc}接收到的流量转发向哪个IP或域名?"
    read -p "请输入: " flag_addr
    [[ -z ${flag_addr} ]] && echo -e "${Error} 地址不能为空" && exit 1
    echo -e "-----------------------------------"
    echo -e "请问你要将本机从${Green}${flag_port}${Nc}接收到的流量转发向${Green}${flag_addr}${Nc}的哪个端口?"
    read -p "请输入: " flag_remote_port
    [[ -z ${flag_remote_port} ]] && echo -e "${Error} 端口不能为空" && exit 1
    flag_remote="${flag_addr}:${flag_remote_port}"
}

write_rawconf(){
    echo "${flag_mode}|${flag_listen}|${flag_remote}" >>"$raw_conf_path"
}

Add_tunnel(){
    check_root
    read_tunnel_mode
    read_listen
    read_remote

    flag_sni="bing.com"
    flag_password="8f0ea803433fbc6a8fa0689313d9d8e3"
    flag_remarks=""

    if [ "$flag_mode" == "client" ]; then
        flag_insecure="true"
        flag_cert=""
        flag_key=""
    else
        flag_insecure="false"
        flag_cert="$work_dir/cert.pem"
        flag_key="$work_dir/key.pem"
    fi

    write_rawconf

    generate_yaml_config
    systemctl restart anyst 2>/dev/null
    echo -e "${Info} 隧道配置已添加并生效"
    echo -e "--------------------------------------------------------"
    show_all_conf
}

generate_yaml_config(){
    cat > "$config_path" <<'YAMLHEADER'
log_level: "info"

tunnels:
YAMLHEADER

    if [ ! -s "$raw_conf_path" ]; then
        echo "  []" >>"$config_path"
        return
    fi

    while IFS='|' read -r mode listen remote; do
        [ -z "$mode" ] && continue

        cat >>"$config_path" <<TUNNEL
  - listen: "${listen}"
    remotes:
      - "${remote}"
    sni: "bing.com"
    password: "8f0ea803433fbc6a8fa0689313d9d8e3"
TUNNEL

        if [ "$mode" == "client" ]; then
            echo "    insecure: true" >>"$config_path"
        else
            echo "    cert: \"$work_dir/cert.pem\"" >>"$config_path"
            echo "    key: \"$work_dir/key.pem\"" >>"$config_path"
        fi
        echo "" >>"$config_path"
    done <"$raw_conf_path"
}

show_all_conf(){
    echo -e "                      ${Green}Anyst 隧道配置${Nc}"
    echo -e "--------------------------------------------------------"
    echo -e " 序号|   模式   |   监听地址    |   目标地址"
    echo -e "--------------------------------------------------------"

    if [ ! -s "$raw_conf_path" ]; then
        echo -e "        ${Yellow}(暂无配置)${Nc}"
        echo -e "--------------------------------------------------------"
        return
    fi

    local i=1
    while IFS='|' read -r mode listen remote; do
        [ -z "$mode" ] && continue
        if [ "$mode" == "client" ]; then
            mode_str="加密转发"
        else
            mode_str="解密接收"
        fi
        echo -e " $i   | ${mode_str} |  ${listen}   | ${remote}"
        echo -e "--------------------------------------------------------"
        i=$((i + 1))
    done <"$raw_conf_path"
}

Delete_tunnel(){
    check_root
    if [ ! -s "$raw_conf_path" ]; then
        echo -e "${Error} 当前没有任何隧道配置"
        return
    fi

    show_all_conf
    echo ""
    read -p "请输入你要删除的配置编号: " numdelete
    if ! echo "$numdelete" | grep -q '^[0-9]\+$'; then
        echo -e "${Error} 请输入正确的数字"
        return
    fi

    total=$(wc -l <"$raw_conf_path")
    if [ "$numdelete" -gt "$total" ] || [ "$numdelete" -lt 1 ]; then
        echo -e "${Error} 编号超出范围 (1-${total})"
        return
    fi

    sed -i "${numdelete}d" "$raw_conf_path"
    generate_yaml_config
    systemctl restart anyst 2>/dev/null
    echo -e "${Info} 配置已删除，服务已重启"
}


main_menu(){
    clear
    echo && echo -e "                 ${Green}Anyst 一键安装配置脚本${Nc}"
    echo -e "  ${Blue}-----------------------------------------------------${Nc}"
    echo -e "  特性: (1) 本脚本采用 systemd 及配置文件对 anyst 进行管理"
    echo -e "        (2) 支持多组隧道规则同时生效"
    echo -e "        (3) 机器重启后转发不失效"
    echo -e "        (4) 支持 TLS 加密伪装 (SNI)"
    echo -e "  ${Blue}-----------------------------------------------------${Nc}"

    if [ -f "$anyst_bin" ]; then
        if systemctl is-active --quiet anyst 2>/dev/null; then
            echo -e "  当前状态: ${Green}已安装${Nc} 并 ${Green}已启动${Nc}"
        else
            echo -e "  当前状态: ${Green}已安装${Nc} 但 ${Red}未启动${Nc}"
        fi
    else
        echo -e "  当前状态: ${Red}未安装${Nc}"
    fi

    echo
    echo -e " ${Green}1.${Nc} 安装 anyst"
    echo -e " ${Green}2.${Nc} 更新 anyst"
    echo -e " ${Green}3.${Nc} 卸载 anyst"
    echo -e " ————————————"
    echo -e " ${Green}4.${Nc} 启动 anyst"
    echo -e " ${Green}5.${Nc} 停止 anyst"
    echo -e " ${Green}6.${Nc} 重启 anyst"
    echo -e " ${Green}7.${Nc} 查看运行状态"
    echo -e " ${Green}8.${Nc} 查看运行日志"
    echo -e " ————————————"
    echo -e " ${Green}9.${Nc} 新增隧道配置"
    echo -e " ${Green}10.${Nc} 查看所有隧道配置"
    echo -e " ${Green}11.${Nc} 删除隧道配置"
    echo
    read -e -p " 请输入数字 [1-11]:" num

    case "$num" in
        1)
            Install_anyst
            ;;
        2)
            Update_anyst
            ;;
        3)
            Uninstall_anyst
            ;;
        4)
            Start_anyst
            ;;
        5)
            Stop_anyst
            ;;
        6)
            Restart_anyst
            ;;
        7)
            Status_anyst
            ;;
        8)
            View_log
            ;;
        9)
            Add_tunnel
            ;;
        10)
            show_all_conf
            ;;
        11)
            Delete_tunnel
            ;;
        *)
            echo -e "${Error} 请输入正确数字 [1-11]"
            ;;
    esac
}

if [[ -n "$1" ]]; then
    Install_anyst "$1"
else
    main_menu
fi
