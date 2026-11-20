#!/bin/bash

# 颜色定义
Green="\033[32m"        # 绿色
Red="\033[31m"          # 红色
Yellow="\033[0;33m"     # 黄色
Blue="\033[0;34m"       # 蓝色
Plain="\033[0m"         # 重置颜色
Green_background="\033[42;37m"  # 绿底
Red_background="\033[41;37m"    # 红底
Yellow_globa="\033[43;37m"      # 黄底
Blue_globa="\033[44;37m"        # 蓝底

# 状态提示
Info="${Green}[信息]${Plain}"
Error="${Red}[错误]${Plain}"
Warning="${Yellow}[警告]${Plain}"
Success="${Green}[成功]${Plain}"
Tip="${Yellow}[提示]${Plain}"

# check root
[[ $EUID -ne 0 ]] && echo -e "${Error} 请以root权限运行此脚本 \n " && exit 1

check_arch(){
    arch=$(arch)
    if [[ $arch == "x86_64" || $arch == "x64" || $arch == "amd64" ]]; then
        arch="amd64"
    elif [[ $arch == i*86 || $arch == "x86" ]]; then
        arch="386"
    elif [[ $arch == "aarch64" || $arch == "arm64" || $arch == armv8* ]]; then
        arch="arm64"
    elif [[ $arch == "armv7l" || $arch == "armv7" || $arch == arm* ]]; then
        arch="armv7"
    elif [[ $arch == "armv6l" || $arch == "armv6" ]]; then
        arch="armv6"
    elif [[ $arch == "armv5l" || $arch == "armv5" ]]; then
        arch="armv5"
    elif [[ $arch == "s390x" ]]; then
        arch="s390x"
    else
        echo -e "${Error} 检测到您的架构不支持，请联系作者！${Plain}"
        exit 1
    fi

    echo -e "${Info} 架构: ${Green}${arch}${Plain}"
}

check_release(){
    if [[ -e /etc/os-release ]]; then
        . /etc/os-release
        release=$ID
    elif [[ -e /usr/lib/os-release ]]; then
        . /usr/lib/os-release
        release=$ID
    fi
    os_version=$(echo $VERSION_ID | cut -d \" -f2 | cut -d . -f1)

    if [[ "${release}" == "arch" ]]; then
        echo -e "${Info} 您的系统是 Arch Linux${Plain}"
    elif [[ "${release}" == "parch" ]]; then
        echo -e "${Info} 您的系统是 Parch linux${Plain}"
    elif [[ "${release}" == "manjaro" ]]; then
        echo -e "${Info} 您的系统是 Manjaro${Plain}"
    elif [[ "${release}" == "armbian" ]]; then
        echo -e "${Info} 您的系统是 Armbian${Plain}"
    elif [[ "${release}" == "opensuse-tumbleweed" ]]; then
        echo -e "${Info} 您的系统是 OpenSUSE Tumbleweed${Plain}"
    elif [[ "${release}" == "centos" ]]; then
        if [[ ${os_version} -lt 9 ]]; then
            echo -e "${Error} 请使用CentOS 9或以上版本!${Plain}\n" && exit 1
        fi
    elif [[ "${release}" == "ubuntu" ]]; then
        if [[ ${os_version} -lt 22 ]]; then
            echo -e "${Error} 请使用Ubuntu 22或以上版本!${Plain}\n" && exit 1
        fi
    elif [[ "${release}" == "rhel" ]]; then
        echo -e "${Info} 您的系统是 Red Hat Enterprise Linux${Plain}"
    elif [[ "${release}" == "fedora" ]]; then
        if [[ ${os_version} -lt 36 ]]; then
            echo -e "${Error} 请使用Fedora 36或以上版本!${Plain}\n" && exit 1
        fi
    elif [[ "${release}" == "debian" ]]; then
        if [[ ${os_version} -lt 11 ]]; then
            echo -e "${Error} 请使用Debian 12或以上版本!${Plain}\n" && exit 1
        fi
    elif [[ "${release}" == "almalinux" ]]; then
        if [[ ${os_version} -lt 95 ]]; then
            echo -e "${Error} 请使用AlmaLinux 9.5或以上版本!${Plain}\n" && exit 1
        fi
    elif [[ "${release}" == "rocky" ]]; then
        if [[ ${os_version} -lt 95 ]]; then
            echo -e "${Error} 请使用Rocky Linux 9.5或以上版本!${Plain}\n" && exit 1
        fi
    elif [[ "${release}" == "ol" ]]; then
        if [[ ${os_version} -lt 8 ]]; then
            echo -e "${Error} 请使用Oracle Linux 8或以上版本!${Plain}\n" && exit 1
        fi
    else
        echo -e "${Error} 您的操作系统不支持此脚本.${Plain}\n"
        echo "请确保您正在使用以下受支持的操作系统之一:"
        echo "- Ubuntu 22.04+"
        echo "- Debian 12+"
        echo "- CentOS 9+"
        echo "- Fedora 36+"
        echo "- Red Hat Enterprise Linux"
        echo "- Arch Linux"
        echo "- Parch Linux"
        echo "- Manjaro"
        echo "- Armbian"
        echo "- AlmaLinux 9.5+"
        echo "- Rocky Linux 9.5+"
        echo "- Oracle Linux 8+"
        echo "- OpenSUSE Tumbleweed"
        exit 1
    fi
}

check_pmc(){
    check_release
    if [[ "$release" == "debian" || "$release" == "ubuntu" || "$release" == "kali" || "$release" == "armbian" ]]; then
        updates="apt update -y"
        installs="apt install -y"
        apps=("wget" "curl" "tar" "openssl" )
    elif [[ "$release" == "alpine" ]]; then
        updates="apk update"
        installs="apk add --no-cache"
        apps=("wget" "curl" "tar" "openssl" )
    elif [[ "$release" == "almalinux" || "$release" == "rocky" || "$release" == "oracle" || "$release" == "centos" ]]; then
        updates="yum update -y"
        installs="yum install -y"
        apps=("wget" "curl" "tar" "openssl" )
    elif [[ "$release" == "fedora" || "$release" == "amzn" || "$release" == "rhel" ]]; then
        updates="dnf update -y"
        installs="dnf install -y"
        apps=("wget" "curl" "tar" "openssl" )
    elif [[ "$release" == "arch" || "$release" == "manjaro" || "$release" == "parch" ]]; then
        updates="pacman -Sy"
        installs="pacman -S --noconfirm"
        apps=("wget" "curl" "tar" "openssl" )
    elif [[ "$release" == "opensuse" || "$release" == "opensuse-leap" || "$release" == "opensuse-tumbleweed" ]]; then
        updates="zypper refresh"
        installs="zypper install -y"
        apps=("wget" "curl" "tar" "openssl" )
    fi
}

install_base(){
    check_pmc
    DEPS=()  # 重要：初始化数组
    cmds=("wget" "curl" "tar" "openssl" )

    for i in "${!cmds[@]}"; do
        if ! command -v "${cmds[i]}" &>/dev/null; then
            DEPS+=("${apps[i]}")
        fi
    done
    
    if [ ${#DEPS[@]} -gt 0 ]; then
        echo -e "${Tip} 安装依赖列表：${Green}${DEPS[*]}${Plain} 请稍后..."
        $updates 
        $installs "${DEPS[@]}" 
        echo -e "${Success} 依赖安装完成！${Plain}"
    else
        echo -e "${Success} 所有依赖已存在，不需要额外安装。${Plain}"
    fi
}

gen_random_string(){
    local length="$1"
    openssl rand -base64 $((length * 2)) \
        | tr -dc 'a-zA-Z0-9' \
        | head -c "$length"
}

config_after_install(){
    echo -e "${Info} 正在配置面板设置..."

    local URL_lists=(
        "https://api4.ipify.org"
        "https://ipv4.icanhazip.com"
        "https://v4.api.ipinfo.io/ip"
        "https://ipv4.myexternalip.com/raw"
        "https://4.ident.me"
        "https://check-host.net/ip"
    )
    local server_ip=""
    
    echo -e "${Info} 正在获取服务器公网 IP..."
    for ip_address in "${URL_lists[@]}"; do
        local response=$(curl -s -w "\n%{http_code}" --max-time 3 "${ip_address}" 2> /dev/null)
        local http_code=$(echo "$response" | tail -n1)
        local ip_result=$(echo "$response" | head -n-1 | tr -d '[:space:]"')
        if [[ "${http_code}" == "200" && "${ip_result}" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            server_ip="${ip_result}"
            echo -e "${Success} 检测到服务器 IP: ${Green}${server_ip}${Plain}"
            break
        fi
    done

    if [[ -z "$server_ip" ]]; then
        echo -e "${Warning} 无法从任何服务商自动检测到服务器 IP。${Plain}"
        while [[ -z "$server_ip" ]]; do
            read -rp "$(echo -e "${Tip} 请输入服务器的公网 IPv4 地址: ")" server_ip
            server_ip="${server_ip// /}"
            if [[ ! "$server_ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                echo -e "${Error} 无效的 IPv4 地址，请重新输入。${Plain}"
                server_ip=""
            fi
        done
    fi

    if [ ! -f "/usr/local/s-ui/db/s-ui.db" ]; then
        local config_path=app
        local config_subPort=2094
        local config_subPath=sub
            
        read -rp "$(echo -e "${Tip} 是否自定义面板设置？(y/N, 默认N): ")" set_config
        if [[ "${set_config}" == "y" || "${set_config}" == "Y" ]]; then
            # 设置端口
            read -rp "$(echo -e "${Tip} 是否自定义面板端口？(y/n, 留空将自动生成): ")" config_confirm
            if [[ "${config_confirm}" == "y" || "${config_confirm}" == "Y" ]]; then
                while true; do
                    read -rp "$(echo -e "${Tip} 请输入面板端口 (10000-65535): ")" config_port
                    if [[ "$config_port" =~ ^[0-9]+$ ]] && [ "$config_port" -ge 10000 ] && [ "$config_port" -le 65535 ]; then
                        echo -e "${Info} 面板端口: ${Green}${config_port}${Plain}"
                        break
                    else
                        echo -e "${Error} 无效输入，请输入 10000-65535 之间的数字。${Plain}"
                    fi
                done
            else
                config_port=$(shuf -i 10000-65535 -n 1)
                echo -e "${Info} 已生成随机端口: ${Green}${config_port}${Plain}"
            fi

            # 设置用户名
            read -rp "$(echo -e "${Tip} 请设置您的用户名 (留空将自动生成): ")" config_username
            if [[ -z "${config_username}" ]]; then
                config_username=$(gen_random_string 7)
                echo -e "${Info} 您的用户名将设定为: ${Green}${config_username}${Plain}"
            fi
        
            # 设置密码
            read -rp "$(echo -e "${Tip} 请设置您的用户密码 (留空将自动生成): ")" config_password
            if [[ -z "${config_password}" ]]; then
                config_password=$(gen_random_string 9)
                echo -e "${Info} 您的用户密码将设定为: ${Green}${config_password}${Plain}"
            fi
        else
            config_port=$(shuf -i 10000-65535 -n 1)
            local config_username=admin
            local config_password=admin
        fi
        
        echo -e "${Info} 正在应用面板配置..."
        /usr/local/s-ui/sui admin -username ${config_username} -password ${config_password} &>/dev/null
        /usr/local/s-ui/sui setting -port ${config_port} -path ${config_path} -subPort ${config_subPort} -subPath ${config_subPath} &>/dev/null

        # Display final credentials and access information
        echo ""
        echo -e "${Green}═══════════════════════════════════════════════════════${Plain}"
        echo -e "${Green}                    面板安装完成！                      ${Plain}"
        echo -e "${Green}═══════════════════════════════════════════════════════${Plain}"
        echo -e "${Green}用户名:     ${Plain}${config_username}"
        echo -e "${Green}密码:       ${Plain}${config_password}"
        echo -e "${Green}端口:       ${Plain}${config_port}"
        echo -e "${Green}Web根路径:  ${Plain}${config_path}"
        echo -e "${Green}访问地址:   ${Plain}${Yellow}http://${server_ip}:${config_port}/${config_path}${Plain}"
        echo -e "${Green}═══════════════════════════════════════════════════════${Plain}"
        echo -e "${Warning} ⚠ 重要：请妥善保存这些凭据！${Plain}"
        echo -e "${Warning} ⚠ 面板使用纯 HTTP 协议，请确保在受信任的网络环境中使用。${Plain}"
        echo -e "${Warning} ⚠ 如需修改配置，请运行 ${Green}s-ui${Plain} 命令。${Plain}"
    else
        local config_username=$(/usr/local/s-ui/sui admin -show | grep "Username:" | awk '{print $NF}')
        local config_port=$(/usr/local/s-ui/sui setting -show | grep "Panel port:" | awk '{print $NF}')
        local config_path=$(/usr/local/s-ui/sui setting -show | grep "Panel path:" | awk '{print $NF}' | sed -e 's/^\///' -e 's/\/$//')
        echo ""
        echo -e "${Green}═══════════════════════════════════════════════════════${Plain}"
        echo -e "${Green}                    面板升级完成！                      ${Plain}"
        echo -e "${Green}═══════════════════════════════════════════════════════${Plain}"
        echo -e "${Green}用户名:     ${Plain}${config_username}"
        echo -e "${Green}端口:       ${Plain}${config_port}"
        echo -e "${Green}Web根路径:  ${Plain}${config_path}"
        echo -e "${Green}访问地址:   ${Plain}${Yellow}http://${server_ip}:${config_port}/${config_path}${Plain}"
        echo -e "${Green}═══════════════════════════════════════════════════════${Plain}"
        echo -e "${Warning} ⚠ 重要：请妥善保存这些凭据！${Plain}"
        echo -e "${Warning} ⚠ 面板使用纯 HTTP 协议，请确保在受信任的网络环境中使用。${Plain}"
        echo -e "${Warning} ⚠ 如需修改配置，请运行 ${Green}s-ui${Plain} 命令。${Plain}"
    fi
}

prepare_services(){
    if [[ -f "/etc/systemd/system/sing-box.service" ]]; then
        echo -e "${Warning} 停止 sing-box 服务... ${Plain}"
        systemctl stop sing-box
        rm -f /usr/local/s-ui/bin/sing-box /usr/local/s-ui/bin/runSingbox.sh /usr/local/s-ui/bin/signal
        echo -e "${Success} sing-box 服务已停止并清理${Plain}"
    fi
    if [[ -e "/usr/local/s-ui/bin" ]]; then
        echo -e "${Green}###############################################################${Plain}"
        echo -e "${Warning} /usr/local/s-ui/bin${Plain} 目录是否存在!"
        echo -e "${Tip} 请检查内容并在迁移后手动删除。 ${Plain}"
        echo -e "${Green}###############################################################${Plain}"
    fi
    systemctl daemon-reload
}

install_s-ui(){
    check_arch
    cd /tmp/

    if [ $# == 0 ]; then
        echo -e "${Info} 正在获取最新版本信息...${Plain}"
        last_version=$(curl -Ls "https://api.github.com/repos/bryet/s-ui/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
        if [[ ! -n "$last_version" ]]; then
            echo -e "${Error} 无法获取 s-ui 版本，这可能是由于 GitHub API 限制所致，请稍后再试${Plain}"
            exit 1
        fi
        echo -e "${Success} 已获取 S-UI 最新版本: ${Green}${last_version}${Plain}，开始安装..."
        wget --no-check-certificate -O /tmp/s-ui-linux-${arch}.tar.gz https://github.com/bryet/s-ui/releases/download/${last_version}/s-ui-linux-${arch}.tar.gz
        if [[ $? -ne 0 ]]; then
            echo -e "${Error} 下载 s-ui 失败，请确保您的服务器能够访问 GitHub ${Plain}"
            exit 1
        fi
    else
        last_version=$1
        url="https://github.com/bryet/s-ui/releases/download/${last_version}/s-ui-linux-${arch}.tar.gz"
        echo -e "${Info} 开始安装 S-UI ${last_version}${Plain}"
        wget --no-check-certificate -O /tmp/s-ui-linux-${arch}.tar.gz ${url}
        if [[ $? -ne 0 ]]; then
            echo -e "${Error} 下载 s-ui ${last_version} 失败，请确认该版本是否存在。${Plain}"
            exit 1
        fi
    fi

    if [[ -e /usr/local/s-ui/ ]]; then
        echo -e "${Info} 检测到已安装的 S-UI，正在停止服务...${Plain}"
        systemctl stop s-ui
    fi

    echo -e "${Info} 正在解压文件...${Plain}"
    tar zxvf s-ui-linux-${arch}.tar.gz
    rm s-ui-linux-${arch}.tar.gz -f

    cp -rf s-ui/s-ui.sh /usr/bin/s-ui
    chmod +x /usr/bin/s-ui
    cp -rf s-ui /usr/local/
    cp -f s-ui/*.service /etc/systemd/system/
    rm -rf s-ui
    config_after_install
    prepare_services
    systemctl enable s-ui --now
    echo
    echo -e "${Green}s-ui ${last_version}${Plain} 安装完成，现在已经正常运行了..."
    echo
    s-ui help
}

install_base
install_s-ui $1