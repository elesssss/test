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

# 检查 root 权限
[[ $EUID -ne 0 ]] && echo -e "${Error} 您必须以管理员身份运行此脚本! \n" && exit 1

# 检测操作系统
if [[ -f /etc/os-release ]]; then
    source /etc/os-release
    release=$ID
elif [[ -f /usr/lib/os-release ]]; then
    source /usr/lib/os-release
    release=$ID
else
    echo -e "${Error} 无法检测系统操作系统，请联系作者!${Plain}" >&2
    exit 1
fi

gen_random_string(){
    local length="$1"
    openssl rand -base64 $((length * 2)) \
        | tr -dc 'a-zA-Z0-9' \
        | head -c "$length"
}

get_public_ip(){
    InFaces=($(ls /sys/class/net | grep -E '^(eth|ens|enp)'))
    IP_API=(
        "http://ip.gs"
        "http://ip.sb"
        "http://ident.me"
        "http://ifconfig.me"
        "http://api.ipify.org"
        "http://icanhazip.com"
    )

    for iface in "${InFaces[@]}"; do
        for ip_api in "${IP_API[@]}"; do
            IPv4=$(curl -s4 --max-time 2 --interface "$iface" "$ip_api")
            IPv6=$(curl -s6 --max-time 2 --interface "$iface" "$ip_api")

            if [[ -n ${IPv4} || -n ${IPv6} ]]; then # 检查是否获取到IP地址
                break 2 # 获取到任一IP类型停止循环
            fi
        done
    done
    
    if [[ -n ${IPv4} ]]; then
        server_ip=${IPv4}
    else
        server_ip=${IPv6}
    fi
}

confirm(){
    if [[ $# > 1 ]]; then
        echo && read -p "$1 [默认$2]: " temp
        if [[ x"${temp}" == x"" ]]; then
            temp=$2
        fi
    else
        read -p "$1 [y/n]: " temp
    fi
    if [[ x"${temp}" == x"y" || x"${temp}" == x"Y" ]]; then
        return 0
    else
        return 1
    fi
}

confirm_restart(){
    confirm "${1} 重新启动服务" "y"
    if [[ $? == 0 ]]; then
        restart
    else
        show_menu
    fi
}

before_show_menu(){
    echo && echo -n -e "${Tip} 按下回车键返回主菜单: ${Plain}" && read temp
    show_menu
}

install(){
    echo -e "${Info} 正在执行安装脚本...${Plain}"
    bash <(curl -Ls https://raw.githubusercontent.com/bryet/s-ui/main/install.sh)
    check_status "$1"
    if [[ $? == 0 ]]; then
        echo -e "${Success} 安装成功！${Plain}"
        if [[ $# == 0 ]]; then
            start
        else
            start 0
        fi
    else
        echo -e "${Error} 安装失败！${Plain}"
    fi
}

update(){
    confirm "此功能将强制重新安装最新版本，且数据不会丢失。您确定要继续吗?" "n"
    if [[ $? != 0 ]]; then
        echo -e "${Error} 取消${Plain}"
        if [[ $# == 0 ]]; then
            before_show_menu
        fi
        return 0
    fi
    echo -e "${Info} 正在执行更新脚本...${Plain}"
    bash <(curl -Ls https://raw.githubusercontent.com/bryet/s-ui/main/install.sh)
    if [[ $? == 0 ]]; then
        echo -e "${Success} 更新已完成，面板已自动重启${Plain}"
        exit 0
    else
        echo -e "${Error} 更新失败！${Plain}"
    fi
}

custom_version(){
    echo -e "${Tip} 请输入面板版本（如0.0.1）:${Plain}"
    read panel_version

    if [ -z "$panel_version" ]; then
        echo -e "${Error} 面板版本不能为空。退出.${Plain}"
        exit 1
    fi

    download_link="https://raw.githubusercontent.com/bryet/s-ui/main/install.sh"
    install_command="bash <(curl -Ls $download_link) $panel_version"

    echo -e "${Info} 下载并安装面板版本 ${Green}${panel_version}${Plain}..."
    eval $install_command
}

uninstall(){
    confirm "您确定要卸载该面板吗?" "n"
    if [[ $? != 0 ]]; then
        if [[ $# == 0 ]]; then
            show_menu
        fi
        return 0
    fi
    
    echo -e "${Info} 正在停止服务...${Plain}"
    systemctl stop s-ui
    systemctl disable s-ui
    rm /etc/systemd/system/s-ui.service -f
    systemctl daemon-reload
    systemctl reset-failed
    
    echo -e "${Info} 正在清理文件...${Plain}"
    rm -rf /etc/s-ui/ /usr/local/s-ui /usr/bin/s-ui
    
    echo ""
    echo -e "${Success} 已成功卸载.${Plain}"
    echo ""

    if [[ $# == 0 ]]; then
        before_show_menu
    fi
}

set_admin(){
    read -rp "$(echo -e "${Tip} 是否设置新的用户名密码？(y/N, 留空使用默认用户名密码): ")" set_config_username
    if [[ "${set_config_username}" == "y" || "${set_config_username}" == "Y" ]]; then
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
        local config_username=admin
        local config_password=admin
    fi
    get_public_ip
    local config_port=$(/usr/local/s-ui/sui setting -show | grep "Panel port:" | awk '{print $NF}')
    local config_path=$(/usr/local/s-ui/sui setting -show | grep "Panel path:" | awk '{print $NF}' | sed -e 's/^\///' -e 's/\/$//')
    /usr/local/s-ui/sui admin -username ${config_username} -password ${config_password} &>/dev/null
    echo -e "${Success} 管理员凭据已更新！${Plain}"
    echo
    echo -e "${Green}═══════════════════════════════════════════════════════${Plain}"
    echo -e "${Green}用户名:     ${Plain}${config_username}"
    echo -e "${Green}密码:       ${Plain}${config_password}"
    echo -e "${Green}访问地址:   ${Plain}${Yellow}http://${server_ip}:${config_port}/${config_path}${Plain}"
    echo -e "${Green}═══════════════════════════════════════════════════════${Plain}"
    echo -e "${Warning} ⚠ 重要：请妥善保存这些凭据！${Plain}"
    echo -e "${Warning} ⚠ 面板使用纯 HTTP 协议，请确保在受信任的网络环境中使用。${Plain}"
    echo
    before_show_menu
}

view_admin(){
    echo -e "${Info} 当前管理员凭据:${Plain}"
    /usr/local/s-ui/sui admin -show
    before_show_menu
}

reset_setting(){
    confirm "您确定要将设置重置为默认值吗?" "n"
    if [[ $? == 0 ]]; then
        /usr/local/s-ui/sui setting -reset
        echo -e "${Success} 面板设置已重置为默认值${Plain}"
    fi
    before_show_menu
}

set_setting(){
    echo -e "${Tip} 请输入${Yellow}面板端口${Plain} (默认值则留空):"
    read config_port
    echo -e "${Tip} 请输入${Yellow}面板路径${Plain} (默认值则留空):"
    read config_path

    echo -e "${Tip} 请输入${Yellow}订阅端口${Plain} (默认值则留空):"
    read config_subPort
    echo -e "${Tip} 请输入${Yellow}订阅路径${Plain} (默认值则留空):" 
    read config_subPath

    echo -e "${Info} 正在初始化，请稍候...${Plain}"
    params=""
    [ -z "$config_port" ] || params="$params -port $config_port"
    [ -z "$config_path" ] || params="$params -path $config_path"
    [ -z "$config_subPort" ] || params="$params -subPort $config_subPort"
    [ -z "$config_subPath" ] || params="$params -subPath $config_subPath"
    
    if [ -n "$params" ]; then
        /usr/local/s-ui/sui setting ${params}
        echo -e "${Success} 面板设置已更新！${Plain}"
    else
        echo -e "${Warning} 未修改任何设置。${Plain}"
    fi
    before_show_menu
}

view_setting(){
    echo -e "${Info} 当前面板设置:${Plain}"
    /usr/local/s-ui/sui setting -show
    view_uri
    before_show_menu
}

view_uri(){
    info=$(/usr/local/s-ui/sui uri)
    if [[ $? != 0 ]]; then
        echo -e "${Error} 获取当前URI错误${Plain}"
        before_show_menu
    fi
    echo -e "${Info} 您可以通过以下URL访问该面板:${Plain}"
    echo -e "${Green}${info}${Plain}"
}

start(){
    check_status $1
    if [[ $? == 0 ]]; then
        echo ""
        echo -e "${Info} ${1} 正在运行，无需重新启动。如果您需要重新启动，请选择重新启动${Plain}"
    else
        systemctl start $1
        sleep 2
        check_status "$1"
        if [[ $? == 0 ]]; then
            echo -e "${Success} ${1} 已成功启动${Plain}"
        else
            echo -e "${Error} ${1} 启动失败，可能是因为启动时间超过了两秒，请稍后查看日志信息${Plain}"
        fi
    fi

    if [[ $# == 1 ]]; then
        before_show_menu
    fi
}

stop(){
    check_status "$1"
    if [[ $? == 1 ]]; then
        echo ""
        echo -e "${Info} ${1} 已停止，无需再次停止!${Plain}"
    else
        systemctl stop "$1"
        sleep 2
        check_status "$1"
        if [[ $? == 1 ]]; then
            echo -e "${Success} ${1} 成功停止${Plain}"
        else
            echo -e "${Error} ${1} 停止失败，请检查日志: journalctl -u $1${Plain}"
        fi
    fi

    if [[ $# == 1 ]]; then
        before_show_menu
    fi
}

restart(){
    echo -e "${Info} 正在重启 ${1}...${Plain}"
    systemctl restart $1
    sleep 2
    check_status $1
    if [[ $? == 0 ]]; then
        echo -e "${Success} ${1} 重启成功${Plain}"
    else
        echo -e "${Error} ${1} 无法重新启动，可能是因为启动时间超过了两秒钟，请稍后查看日志信息。${Plain}"
    fi
    if [[ $# == 1 ]]; then
        before_show_menu
    fi
}

status(){
    systemctl status s-ui -l
    if [[ $# == 0 ]]; then
        before_show_menu
    fi
}

enable(){
    systemctl enable $1
    if [[ $? == 0 ]]; then
        echo -e "${Success} ${1} 已成功设置为开机自启${Plain}"
    else
        echo -e "${Error} ${1} 无法设置开机自启${Plain}"
    fi

    if [[ $# == 1 ]]; then
        before_show_menu
    fi
}

disable(){
    systemctl disable $1
    if [[ $? == 0 ]]; then
        echo -e "${Success} ${1} 开机自启已成功取消${Plain}"
    else
        echo -e "${Error} ${1} 无法取消开机自启${Plain}"
    fi

    if [[ $# == 1 ]]; then
        before_show_menu
    fi
}

show_log(){
    echo -e "${Info} 正在查看 ${1} 日志 (Ctrl+C 退出)${Plain}"
    journalctl -u $1.service -e --no-pager -f
    if [[ $# == 1 ]]; then
        before_show_menu
    fi
}

update_shell(){
    echo -e "${Info} 正在更新管理脚本...${Plain}"
    wget -O /usr/bin/s-ui --no-check-certificate https://raw.githubusercontent.com/bryet/s-ui/main/s-ui.sh
    if [[ $? != 0 ]]; then
        echo ""
        echo -e "${Error} 无法下载脚本，请检查机器是否能连接GitHub${Plain}"
        before_show_menu
    else
        chmod +x /usr/bin/s-ui
        echo -e "${Success} 脚本更新成功，请重新运行该脚本${Plain}" && exit 0
    fi
}

check_status(){
    if [[ ! -f "/etc/systemd/system/$1.service" ]]; then
        return 2
    fi
    temp=$(systemctl status "$1" | grep Active | awk '{print $3}' | cut -d "(" -f2 | cut -d ")" -f1)
    if [[ x"${temp}" == x"running" ]]; then
        return 0
    else
        return 1
    fi
}

check_enabled(){
    temp=$(systemctl is-enabled $1)
    if [[ x"${temp}" == x"enabled" ]]; then
        return 0
    else
        return 1
    fi
}

check_uninstall(){
    check_status s-ui
    if [[ $? != 2 ]]; then
        echo ""
        echo -e "${Error} 面板已安装完毕，请勿重新安装${Plain}"
        if [[ $# == 0 ]]; then
            before_show_menu
        fi
        return 1
    else
        return 0
    fi
}

check_install(){
    check_status s-ui
    if [[ $? == 2 ]]; then
        echo ""
        echo -e "${Error} 请先安装面板${Plain}"
        if [[ $# == 0 ]]; then
            before_show_menu
        fi
        return 1
    else
        return 0
    fi
}

show_status(){
    check_status $1
    case $? in
    0)
        echo -e "${1} 状态: ${Green}运行中${Plain}"
        show_enable_status $1
        ;;
    1)
        echo -e "${1} 状态: ${Yellow}未运行${Plain}"
        show_enable_status $1
        ;;
    2)
        echo -e "${1} 状态: ${Red}未安装${Plain}"
        ;;
    esac
}

show_enable_status(){
    check_enabled $1
    if [[ $? == 0 ]]; then
        echo -e "${1} 开机自启: ${Green}是${Plain}"
    else
        echo -e "${1} 开机自启: ${Red}否${Plain}"
    fi
}

check_s-ui_status(){
    count=$(ps -ef | grep "sui" | grep -v "grep" | wc -l)
    if [[ count -ne 0 ]]; then
        return 0
    else
        return 1
    fi
}

show_s-ui_status(){
    check_s-ui_status
    if [[ $? == 0 ]]; then
        echo -e "s-ui 进程状态: ${Green}运行中${Plain}"
    else
        echo -e "s-ui 进程状态: ${Red}未运行${Plain}"
    fi
}

bbr_menu(){
    echo -e "${Green}\t1.${Plain} 开启 BBR"
    echo -e "${Green}\t2.${Plain} 关闭 BBR"
    echo -e "${Green}\t0.${Plain} 返回主菜单"
    read -p "选择一个选项: " choice
    case "$choice" in
    0)
        show_menu
        ;;
    1)
        enable_bbr
        ;;
    2)
        disable_bbr
        ;;
    *) echo -e "${Error} 选择无效${Plain}" ;;
    esac
}

disable_bbr(){
    if ! grep -q "net.core.default_qdisc=fq" /etc/sysctl.conf || ! grep -q "net.ipv4.tcp_congestion_control=bbr" /etc/sysctl.conf; then
        echo -e "${Warning} BBR 当前未启用.${Plain}"
        exit 0
    fi
    sed -i 's/net.core.default_qdisc=fq/net.core.default_qdisc=pfifo_fast/' /etc/sysctl.conf
    sed -i 's/net.ipv4.tcp_congestion_control=bbr/net.ipv4.tcp_congestion_control=cubic/' /etc/sysctl.conf
    sysctl -p
    if [[ $(sysctl net.ipv4.tcp_congestion_control | awk '{print $3}') == "cubic" ]]; then
        echo -e "${Success} BBR 已成功替换为 CUBIC.${Plain}"
    else
        echo -e "${Error} 无法将BBR替换为CUBIC。请检查您的系统配置.${Plain}"
    fi
}

enable_bbr(){
    if grep -q "net.core.default_qdisc=fq" /etc/sysctl.conf && grep -q "net.ipv4.tcp_congestion_control=bbr" /etc/sysctl.conf; then
        echo -e "${Success} BBR 已启用!${Plain}"
        exit 0
    fi
    case "${release}" in
    ubuntu | debian | armbian)
        apt-get update && apt-get install -yqq --no-install-recommends ca-certificates
        ;;
    centos | almalinux | rocky | oracle)
        yum -y update && yum -y install ca-certificates
        ;;
    fedora | rhel)
        dnf -y update && dnf -y install ca-certificates
        ;;
    arch | manjaro | parch)
        pacman -Sy --noconfirm ca-certificates
        ;;
    *)
        echo -e "${Error} 不支持的操作系统。请检查脚本并手动安装所需的包.${Plain}\n"
        exit 1
        ;;
    esac
    echo "net.core.default_qdisc=fq" | tee -a /etc/sysctl.conf
    echo "net.ipv4.tcp_congestion_control=bbr" | tee -a /etc/sysctl.conf
    sysctl -p
    if [[ $(sysctl net.ipv4.tcp_congestion_control | awk '{print $3}') == "bbr" ]]; then
        echo -e "${Success} BBR 已成功启用.${Plain}"
    else
        echo -e "${Error} 无法启用BBR。请检查您的系统配置.${Plain}"
    fi
}

install_acme(){
    cd ~
    echo -e "${Info} 安装 Acme...${Plain}"
    curl https://get.acme.sh | sh
    if [ $? -ne 0 ]; then
        echo -e "${Error} 安装 Acme 失败${Plain}"
        return 1
    else
        echo -e "${Success} 安装 Acme 成功${Plain}"
    fi
    return 0
}

ssl_cert_issue_main(){
    echo -e "${Green}\t1.${Plain} 申请 SSL 证书"
    echo -e "${Green}\t2.${Plain} 删除 SSL 证书"
    echo -e "${Green}\t3.${Plain} 强制更新 SSL 证书"
    echo -e "${Green}\t4.${Plain} 自签名证书"
    read -p "选择一个选项: " choice
    case "$choice" in
        1) ssl_cert_issue ;;
        2) 
            local domain=""
            read -p "请输入您的域名以删除证书: " domain
            ~/.acme.sh/acme.sh --revoke -d ${domain}
            echo -e "${Success} 证书已删除${Plain}"
            ;;
        3)
            local domain=""
            read -p "请输入您的域名以强制更新SSL证书: " domain
            ~/.acme.sh/acme.sh --renew -d ${domain} --force
            echo -e "${Success} 证书已强制更新${Plain}"
            ;;
        4)
            generate_self_signed_cert
            ;;
        *) echo -e "${Error} 选择无效${Plain}" ;;
    esac
}

ssl_cert_issue(){
    if ! command -v ~/.acme.sh/acme.sh &>/dev/null; then
        echo -e "${Warning} acme.sh 未找到，即将进行安装...${Plain}"
        install_acme
        if [ $? -ne 0 ]; then
            echo -e "${Error} 安装 Acme 失败，请检查日志${Plain}"
            exit 1
        fi
    fi
    case "${release}" in
    ubuntu | debian | armbian)
        apt update && apt install socat -y
        ;;
    centos | almalinux | rocky | oracle)
        yum -y update && yum -y install socat
        ;;
    fedora | rhel)
        dnf -y update && dnf -y install socat
        ;;
    arch | manjaro | parch)
        pacman -Sy --noconfirm socat
        ;;
    *)
        echo -e "${Error} 不支持的操作系统。请检查脚本并手动安装所需的包.${Plain}\n"
        exit 1
        ;;
    esac
    if [ $? -ne 0 ]; then
        echo -e "${Error} 安装 socat 失败，请检查日志${Plain}"
        exit 1
    else
        echo -e "${Success} 成功安装 socat...${Plain}"
    fi

    local domain=""
    read -p "请输入您的域名: " domain
    echo -e "${Info} 您的域名是: ${Green}${domain}${Plain}，检查中..."
    local currentCert=$(~/.acme.sh/acme.sh --list | tail -1 | awk '{print $1}')

    if [ ${currentCert} == ${domain} ]; then
        local certInfo=$(~/.acme.sh/acme.sh --list)
        echo -e "${Error} 系统中已存在证书，无法再次签发，当前证书详细信息如下:${Plain}"
        echo -e "${Info} $certInfo${Plain}"
        exit 1
    else
        echo -e "${Info} 您的域名现已准备好进行证书签发...${Plain}"
    fi

    certPath="/root/cert/${domain}"
    if [ ! -d "$certPath" ]; then
        mkdir -p "$certPath"
    else
        rm -rf "$certPath"
        mkdir -p "$certPath"
    fi

    local WebPort=80
    read -p "请选择您使用的端口，默认端口为80: " WebPort
    if [[ ${WebPort} -gt 65535 || ${WebPort} -lt 1 ]]; then
        echo -e "${Error} 您的输入 ${WebPort} 无效，将使用默认端口${Plain}"
        WebPort=80
    fi
    echo -e "${Info} 将使用端口：${WebPort} 签发证书，请确保该端口已打开...${Plain}"
    
    ~/.acme.sh/acme.sh --set-default-ca --server letsencrypt
    ~/.acme.sh/acme.sh --issue -d ${domain} --standalone --httpport ${WebPort}
    if [ $? -ne 0 ]; then
        echo -e "${Error} 证书签发失败，请检查日志${Plain}"
        rm -rf ~/.acme.sh/${domain}
        exit 1
    else
        echo -e "${Success} 证书签发成功，正在安装证书...${Plain}"
    fi
    
    ~/.acme.sh/acme.sh --installcert -d ${domain} \
        --key-file /root/cert/${domain}/privkey.pem \
        --fullchain-file /root/cert/${domain}/fullchain.pem

    if [ $? -ne 0 ]; then
        echo -e "${Error} 证书安装失败，退出${Plain}"
        rm -rf ~/.acme.sh/${domain}
        exit 1
    else
        echo -e "${Success} 证书安装成功，启用自动续期...${Plain}"
    fi

    ~/.acme.sh/acme.sh --upgrade --auto-upgrade
    if [ $? -ne 0 ]; then
        echo -e "${Error} 自动续期失败，证书详细信息:${Plain}"
        ls -lah cert/*
        chmod 755 $certPath/*
        exit 1
    else
        echo -e "${Success} 自动续期成功，证书详细信息:${Plain}"
        ls -lah cert/*
        chmod 755 $certPath/*
    fi
}

ssl_cert_issue_CF(){
    echo -E ""
    echo -e "${Warning} ******使用说明******${Plain}"
    echo "1) Cloudflare 颁发的全新证书"
    echo "2) 强制续签现有证书"
    echo "3) 返回菜单"
    read -p "请输入您的选择 [1-3]: " choice

    certPath="/root/cert-CF"

    case $choice in
        1|2)
            force_flag=""
            if [ "$choice" -eq 2 ]; then
                force_flag="--force"
                echo -e "${Info} 强制重新签发 SSL 证书...${Plain}"
            else
                echo -e "${Info} 开始 SSL 证书签发...${Plain}"
            fi
            
            echo -e "${Warning} ******使用说明******${Plain}"
            echo -e "${Info} 此Acme脚本需要以下数据:${Plain}"
            echo -e "${Info} 1. Cloudflare 注册 e-mail${Plain}"
            echo -e "${Info} 2. Cloudflare Global API Key${Plain}"
            echo -e "${Info} 3. 通过Cloudflare解析到当前服务器的域名。${Plain}"
            echo -e "${Info} 4. 脚本用于申请证书。默认安装路径为 /root/cert ${Plain}"
            confirm "请确认?" "y"
            if [ $? -eq 0 ]; then
                if ! command -v ~/.acme.sh/acme.sh &>/dev/null; then
                    echo -e "${Warning} acme.sh 无法找到。正在安装...${Plain}"
                    install_acme
                    if [ $? -ne 0 ]; then
                        echo -e "${Error} 安装 Acme 失败，请检查日志。${Plain}"
                        exit 1
                    fi
                fi

                CF_Domain=""
                if [ ! -d "$certPath" ]; then
                    mkdir -p $certPath
                else
                    rm -rf $certPath
                    mkdir -p $certPath
                fi

                echo -e "${Tip} 请设置一个域名:${Plain}"
                read -p "请在此输入您的域名: " CF_Domain
                echo -e "${Info} 您的域名已设置为: ${Green}${CF_Domain}${Plain}"

                CF_GlobalKey=""
                CF_AccountEmail=""
                echo -e "${Tip} 请设置您的 API key:${Plain}"
                read -p "请在此输入您的 API key: " CF_GlobalKey
                echo -e "${Tip} 请设置您注册的电子邮件地址:${Plain}"
                read -p "请在此输入您的电子邮件地址: " CF_AccountEmail

                ~/.acme.sh/acme.sh --set-default-ca --server letsencrypt
                if [ $? -ne 0 ]; then
                    echo -e "${Error} 默认证书颁发机构（CA）Let's Encrypt 失败，脚本退出...${Plain}"
                    exit 1
                fi

                export CF_Key="${CF_GlobalKey}"
                export CF_Email="${CF_AccountEmail}"

                ~/.acme.sh/acme.sh --issue --dns dns_cf -d ${CF_Domain} -d *.${CF_Domain} $force_flag --log
                if [ $? -ne 0 ]; then
                    echo -e "${Error} 证书签发失败，脚本退出...${Plain}"
                    exit 1
                else
                    echo -e "${Success} 证书已成功签发，正在安装中...${Plain}"
                fi

                mkdir -p ${certPath}/${CF_Domain}
                if [ $? -ne 0 ]; then
                    echo -e "${Error} 无法创建目录: ${certPath}/${CF_Domain}${Plain}"
                    exit 1
                fi

                ~/.acme.sh/acme.sh --installcert -d ${CF_Domain} -d *.${CF_Domain} \
                    --fullchain-file ${certPath}/${CF_Domain}/fullchain.pem \
                    --key-file ${certPath}/${CF_Domain}/privkey.pem

                if [ $? -ne 0 ]; then
                    echo -e "${Error} 证书安装失败，脚本退出...${Plain}"
                    exit 1
                else
                    echo -e "${Success} 证书已成功安装，正在启用自动更新...${Plain}"
                fi

                ~/.acme.sh/acme.sh --upgrade --auto-upgrade
                if [ $? -ne 0 ]; then
                    echo -e "${Error} 自动更新设置失败，脚本退出...${Plain}"
                    exit 1
                else
                    echo -e "${Success} 证书已安装且自动续期功能已启用.${Plain}"
                    ls -lah ${certPath}/${CF_Domain}
                    chmod 755 ${certPath}/${CF_Domain}
                fi
            fi
            show_menu
            ;;
        3)
            echo -e "${Info} 退出...${Plain}"
            show_menu
            ;;
        *)
            echo -e "${Error} 选择无效，请重新选择.${Plain}"
            show_menu
            ;;
    esac
}

generate_self_signed_cert(){
    cert_dir="/etc/sing-box"
    mkdir -p "$cert_dir"
    echo -e "${Info} 选择证书类型:${Plain}"
    echo -e "${Green}\t1.${Plain} Ed25519 (*推荐*)"
    echo -e "${Green}\t2.${Plain} RSA 2048"
    echo -e "${Green}\t3.${Plain} RSA 4096"
    echo -e "${Green}\t4.${Plain} ECDSA prime256v1"
    echo -e "${Green}\t5.${Plain} ECDSA secp384r1"
    read -p "请输入您的选择 [1-5, 默认 1]: " cert_type
    cert_type=${cert_type:-1}

    case "$cert_type" in
        1)
            algo="ed25519"
            key_opt="-newkey ed25519"
            ;;
        2)
            algo="rsa"
            key_opt="-newkey rsa:2048"
            ;;
        3)
            algo="rsa"
            key_opt="-newkey rsa:4096"
            ;;
        4)
            algo="ecdsa"
            key_opt="-newkey ec -pkeyopt ec_paramgen_curve:prime256v1"
            ;;
        5)
            algo="ecdsa"
            key_opt="-newkey ec -pkeyopt ec_paramgen_curve:secp384r1"
            ;;
        *)
            algo="ed25519"
            key_opt="-newkey ed25519"
            ;;
    esac

    echo -e "${Info} 生成自签名证书 (${algo})...${Plain}"
    sudo openssl req -x509 -nodes -days 3650 $key_opt \
        -keyout "${cert_dir}/self.key" \
        -out "${cert_dir}/self.crt" \
        -subj "/CN=myserver"
    if [[ $? -eq 0 ]]; then
        sudo chmod 600 "${cert_dir}/self."*
        echo -e "${Success} 自签名证书生成成功!${Plain}"
        echo -e "${Info} 证书路径: ${Green}${cert_dir}/self.crt${Plain}"
        echo -e "${Info} 私钥路径: ${Green}${cert_dir}/self.key${Plain}"
    else
        echo -e "${Error} 无法生成自签名证书.${Plain}"
    fi
    before_show_menu
}

show_usage(){
    echo -e "┌───────────────────────────────────────────────────────┐
│  S-UI 控制菜单使用说明                                │
│                                                       │
│  ${Blue}s-ui${Plain}              - 管理脚本                         │
│  ${Blue}s-ui start${Plain}        - 启动 s-ui                        │
│  ${Blue}s-ui stop${Plain}         - 停止 s-ui                        │
│  ${Blue}s-ui restart${Plain}      - 重启 s-ui                        │
│  ${Blue}s-ui status${Plain}       - s-ui 当前状态                    │
│  ${Blue}s-ui settings${Plain}     - s-ui 当前设置                    │
│  ${Blue}s-ui enable${Plain}       - 开启开机自启                     │
│  ${Blue}s-ui disable${Plain}      - 关闭开机自启                     │
│  ${Blue}s-ui log${Plain}          - 查看 s-ui 日志                   │
│  ${Blue}s-ui update${Plain}       - 更新                             │
│  ${Blue}s-ui install${Plain}      - 安装                             │
│  ${Blue}s-ui uninstall${Plain}    - 卸载                             │
│  ${Blue}s-ui help${Plain}         - 控制菜单使用                     │
└───────────────────────────────────────────────────────┘"
}

show_menu(){
    echo -e "${Green}S-UI 管理脚本 ${Plain}
————————————————————————————————
  ${Green}0.${Plain} 退出
————————————————————————————————
  ${Green}1.${Plain} 安装
  ${Green}2.${Plain} 更新
  ${Green}3.${Plain} 设定版本
  ${Green}4.${Plain} 卸载
————————————————————————————————
  ${Green}5.${Plain} 修改用户名密码
  ${Green}6.${Plain} 查看管理员凭据
————————————————————————————————
  ${Green}7.${Plain} 重置面板设置
  ${Green}8.${Plain} 面板设置
  ${Green}9.${Plain} 查看面板设置
————————————————————————————————
 ${Green}10.${Plain} S-UI 启动
 ${Green}11.${Plain} S-UI 停止
 ${Green}12.${Plain} S-UI 重启
 ${Green}13.${Plain} S-UI 查看状态
 ${Green}14.${Plain} S-UI 查看日志
 ${Green}15.${Plain} S-UI 开启开机自启
 ${Green}16.${Plain} S-UI 关闭开机自启
————————————————————————————————
 ${Green}17.${Plain} 启用或禁用BBR
 ${Green}18.${Plain} SSL 证书管理
 ${Green}19.${Plain} Cloudflare SSL 证书
————————————————————————————————"
    show_status s-ui
    echo && read -p "请输入您的选择 [0-19]: " num

    case "${num}" in
    0)
        exit 0
        ;;
    1)
        check_uninstall && install
        ;;
    2)
        check_install && update
        ;;
    3)
        check_install && custom_version
        ;;
    4)
        check_install && uninstall
        ;;
    5)
        check_install && set_admin
        ;;
    6)
        check_install && view_admin
        ;;
    7)
        check_install && reset_setting
        ;;
    8)
        check_install && set_setting
        ;;
    9)
        check_install && view_setting
        ;;
    10)
        check_install && start s-ui
        ;;
    11)
        check_install && stop s-ui
        ;;
    12)
        check_install && restart s-ui
        ;;
    13)
        check_install && status s-ui
        ;;
    14)
        check_install && show_log s-ui
        ;;
    15)
        check_install && enable s-ui
        ;;
    16)
        check_install && disable s-ui
        ;;
    17)
        bbr_menu
        ;;
    18)
        ssl_cert_issue_main
        ;;
    19)
        ssl_cert_issue_CF
        ;;
    *)
        echo -e "${Error} 请输入正确的数字 [0-19]${Plain}"
        ;;
    esac
}

if [[ $# > 0 ]]; then
    case $1 in
    "start")
        check_install 0 && start s-ui 0
        ;;
    "stop")
        check_install 0 && stop s-ui 0
        ;;
    "restart")
        check_install 0 && restart s-ui 0
        ;;
    "status")
        check_install 0 && status 0
        ;;
    "enable")
        check_install 0 && enable s-ui 0
        ;;
    "disable")
        check_install 0 && disable s-ui 0
        ;;
    "log")
        check_install 0 && show_log s-ui 0
        ;;
    "update")
        check_install 0 && update 0
        ;;
    "install")
        check_uninstall 0 && install 0
        ;;
    "uninstall")
        check_install 0 && uninstall 0
        ;;
    *) show_usage ;;
    esac
else
    show_menu
fi