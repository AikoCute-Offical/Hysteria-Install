#!/bin/bash

RED="\033[31m"
GREEN="\033[32m"
YELLOW="\033[33m"
PLAIN='\033[0m'

red(){
    echo -e "\033[31m\033[01m$1\033[0m"
}

green(){
    echo -e "\033[32m\033[01m$1\033[0m"
}

yellow(){
    echo -e "\033[33m\033[01m$1\033[0m"
}

REGEX=("debian" "ubuntu" "centos|red hat|kernel|oracle linux|alma|rocky" "'amazon linux'")
RELEASE=("Debian" "Ubuntu" "CentOS" "CentOS")
PACKAGE_UPDATE=("apt-get -y update" "apt-get -y update" "yum -y update" "yum -y update")
PACKAGE_INSTALL=("apt -y install" "apt -y install" "yum -y install" "yum -y install")
PACKAGE_REMOVE=("apt -y remove" "apt -y remove" "yum -y remove" "yum -y remove")
PACKAGE_UNINSTALL=("apt -y autoremove" "apt -y autoremove" "yum -y autoremove" "yum -y autoremove")

[[ $EUID -ne 0 ]] && red "Please run the script under root user" && exit 1

CMD=("$(grep -i pretty_name /etc/os-release 2>/dev/null | cut -d \" -f2)" "$(hostnamectl 2>/dev/null | grep -i system | cut -d : -f2)" "$(lsb_release -sd 2>/dev/null)" "$(grep -i description /etc/lsb-release 2>/dev/null | cut -d \" -f2)" "$(grep . /etc/redhat-release 2>/dev/null)" "$(grep . /etc/issue 2>/dev/null | cut -d \\ -f1 | sed '/^[ ]*$/d')") 

for i in "${CMD[@]}"; do
    SYS="$i" && [[ -n $SYS ]] && break
done

for ((int = 0; int < ${#REGEX[@]}; int++)); do
    [[ $(echo "$SYS" | tr '[:upper:]' '[:lower:]') =~ ${REGEX[int]} ]] && SYSTEM="${RELEASE[int]}" && [[ -n $SYSTEM ]] && break
done

[[ $EUID -ne 0 ]] && red "Please run the script under root user" && exit 1

IP=$(curl -s6m8 ip.sb) || IP=$(curl -s4m8 ip.sb)

if [[ -n $(echo $IP | grep ":") ]]; then
    IP="[$IP]"
fi

check_tun(){
    TUN=$(cat /dev/net/tun 2>&1 | tr '[:upper:]' '[:lower:]')
    if [[ ! $TUN =~ 'in bad state' ]] && [[ ! $TUN =~ 'in error state' ]] && [[ ! $TUN =~ 'Die Dateizugriffsnummer ist in schlechter Verfassung' ]]; then
        if [[ $vpsvirt == "openvz" ]]; then
            wget -N --no-check-certificate https://raw.githubusercontent.com/AikoCute-Offical/Tun-install/master/tun.sh && bash tun.sh
        else
            red "It is detected that the TUN module is not enabled, please go to the VPS control panel to enable it" 
            exit 1
        fi
    fi
}

checkCentOS8(){
    if [[ -n $(cat /etc/os-release | grep "CentOS Linux 8") ]]; then
        yellow "It is detected that the current VPS system is CentOS 8. Do you want to upgrade to CentOS Stream 8 to ensure that the packages are installed normally?"
        read -rp "Please enter options [y/n]：" comfirmCentOSStream
        if [[ $comfirmCentOSStream == "y" ]]; then
            yellow "Upgrading to CentOS Stream 8 for you, it should take about 10-30 minutes"
            sleep 1
            sed -i -e "s|releasever|releasever-stream|g" /etc/yum.repos.d/CentOS-*
            yum clean all && yum makecache
            dnf swap centos-linux-repos centos-stream-repos distro-sync -y
        else
            red "The upgrade process has been canceled, the script is about to exit!"
            exit 1
        fi
    fi
}

archAffix(){
    case "$(uname -m)" in
        i686 | i386) echo '386' ;;
        x86_64 | amd64) echo 'amd64' ;;
        armv5tel) echo 'arm-5' ;;
        armv7 | armv7l) echo 'arm-7' ;;
        armv8 | arm64 | aarch64) echo 'arm64' ;;
        s390x) echo 's390x' ;;
        *) red " Unsupported CPU architecture!" && exit 1 ;;
    esac
    return 0
}

install_base() {
    if [[ $SYSTEM != "CentOS" ]]; then
        ${PACKAGE_UPDATE[int]}
    fi
    ${PACKAGE_INSTALL[int]} wget curl sudo
}

downloadHysteria() {
    rm -f /usr/bin/hysteria
    rm -rf /root/Hysteria
    mkdir /root/Hysteria
    last_version=$(curl -Ls "https://api.github.com/repos/HyNetwork/Hysteria/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
    ## last_version=$(curl -Ls "https://data.jsdelivr.com/v1/package/resolve/gh/HyNetwork/Hysteria" | grep '"version":' | sed -E 's/.*"([^"]+)".*/\1/')
    if [[ ! -n "$last_version" ]]; then
        red "Failed to detect Hysteria version, maybe a network error, please try again later"
        exit 1
    fi
    yellow "Hysteria latest version detected：${last_version},start installation"
    wget -N --no-check-certificate https://github.com/HyNetwork/Hysteria/releases/download/v${last_version}/Hysteria-tun-linux-$(archAffix) -O /usr/bin/hysteria
    if [[ $? -ne 0 ]]; then
        red "Failed to download Hysteria, please make sure your server can connect and download Github files"
        exit 1
    fi
    chmod +x /usr/bin/hysteria
}

makeConfig() {
    read -rp "Please enter Hysteria's connection port (default: 40000)：" PORT
    [[ -z $PORT ]] && PORT=40000
    if [[ -n $(netstat -ntlp | grep "$PORT") ]]; then
        until [[ -z $(netstat -ntlp | grep "$PORT") ]]; do
            if [[ -n $(netstat -ntlp | grep "$PORT") ]]; then
                yellow "The port you set is currently occupied, please re-enter the port"
                read -rp "Please enter Hysteria's connection port (default: 40000):" PORT
            fi
        done
    fi
    read -rp "Please enter Hysteria's connection obfuscation password (randomly generated by default)：" OBFS
    [[ -z $OBFS ]] && OBFS=$(date +%s%N | md5sum | cut -c 1-32)
    sysctl -w net.core.rmem_max=4000000
    ulimit -n 1048576 && ulimit -u unlimited
    openssl ecparam -genkey -name prime256v1 -out /root/Hysteria/private.key
    openssl req -new -x509 -days 36500 -key /root/Hysteria/private.key -out /root/Hysteria/cert.crt -subj "/VN=www.aikocute.com"
    cat <<EOF > /root/Hysteria/server.json
{
    "listen": ":$PORT",
    "cert": "/root/Hysteria/cert.crt",
    "key": "/root/Hysteria/private.key",
    "obfs": "$OBFS"
}
EOF
    cat <<EOF > /root/Hysteria/client.json
{
    "server": "$IP:$PORT",
    "obfs": "$OBFS",
    "up_mbps": 200,
    "down_mbps": 1000,
    "insecure": true,
    "socks5": {
        "listen": "127.0.0.1:1080"
    },
    "http": {
        "listen": "127.0.0.1:1081"
    }
}
EOF
    cat <<EOF > /root/Hysteria/v2rayn.json
{
    "server": "$IP:$PORT",
    "obfs": "$OBFS",
    "up_mbps": 200,
    "down_mbps": 1000,
    "insecure": true,
    "acl": "acl/routes.acl",
    "mmdb": "acl/Country.mmdb",
    "retry": 3,
    "retry_interval": 5,
    "socks5": {
        "listen": "127.0.0.1:10808"
    },
    "http": {
        "listen": "127.0.0.1:10809"
    }
}
EOF
    cat <<'TEXT' > /etc/systemd/system/hysteria.service
[Unit]
Description=Hysiteria Server
After=network.target

[Install]
WantedBy=multi-user.target

[Service]
Type=simple
WorkingDirectory=/root/Hysteria
ExecStart=/usr/bin/hysteria -c /root/Hysteria/server.json server
Restart=always
TEXT
    url="hysteria://$IP:$PORT?auth=$OBFS&upmbps=200&downmbps=1000&obfs=xplus&obfsParam=$OBFS"
}

installBBR() {
    result=$(lsmod | grep bbr)
    if [[ $result != "" ]]; then
        green "BBR module installed"
        return
    fi
    res=`systemd-detect-virt`
    if [[ $res =~ openvz|lxc ]]; then
        red "Since your VPS is an OpenVZ or LXC architecture VPS, skip the installation"
        return
    fi
    
    echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
    echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
    sysctl -p
    result=$(lsmod | grep bbr)
    if [[ "$result" != "" ]]; then
        green "BBR module enabled"
        return
    fi

    green "Installing BBR module..."
    if [[ $SYSTEM = "CentOS" ]]; then
        rpm --import https://www.elrepo.org/RPM-GPG-KEY-elrepo.org
        rpm -Uvh http://www.elrepo.org/elrepo-release-7.0-4.el7.elrepo.noarch.rpm
        ${PACKAGE_INSTALL[int]} --enablerepo=elrepo-kernel kernel-ml
        ${PACKAGE_REMOVE[int]} kernel-3.*
        grub2-set-default 0
        echo "tcp_bbr" >> /etc/modules-load.d/modules.conf
    else
        ${PACKAGE_INSTALL[int]} --install-recommends linux-generic-hwe-16.04
        grub-set-default 0
        echo "tcp_bbr" >> /etc/modules-load.d/modules.conf
    fi
}

installHysteria() {
    checkCentOS8
    install_base
    downloadHysteria
    read -rp "Whether to install BBR (y/n, default n)：" INSTALL_BBR_YN
    if [[ $INSTALL_BBR_YN =~ "y"|"Y" ]]; then
        installBBR
    fi
    makeConfig
    systemctl enable hysteria
    systemctl start hysteria
    check_status
    if [[ -n $(service hysteria status 2>/dev/null | grep "inactive") ]]; then
        red "Hysteria Server installation failed"
    elif [[ -n $(service hysteria status 2>/dev/null | grep "active") ]]; then
        show_usage
        green "Hysteria Server installed successfully"
        yellow "The server configuration file has been saved to /root/Hysteria/server.json"
        yellow "Client profile saved to /root/Hysteria/client.json"
        yellow "V2rayN The proxy rule diversion profile has been saved to /root/Hysteria/v2rayn.json"
        yellow "SagerNet / ShadowRocket share link: "
        green "$url"
    fi
}

start_hysteria() {
    systemctl start hysteria
    green "Hysteria Activated!"
}

stop_hysteria() {
    systemctl stop hysteria
    green "Hysteria stopped!"
}

restart(){
    systemctl restart hysteria
    green "Hysteria Rebooted!"
}

view_log(){
    service hysteria status
}

uninstall(){
    systemctl stop hysteria
    systemctl disable hysteria
    rm -rf /root/Hysteria
    rm -f /usr/bin/hysteria /usr/local/bin/hy
    rm -f /etc/systemd/system/hysteria.service
    green "Hysteria Uninstallation complete!"
}

check_status(){
    if [[ -n $(service hysteria status 2>/dev/null | grep "inactive") ]]; then
        status="${RED}Hysteria have not started!${PLAIN}"
    elif [[ -n $(service hysteria status 2>/dev/null | grep "active") ]]; then
        status="${GREEN}Hysteria Activated!${PLAIN}"
    else
        status="${RED}Not Installed Hysteria！${PLAIN}"
    fi
}

open_ports() {
    systemctl stop firewalld.service 2>/dev/null
    systemctl disable firewalld.service 2>/dev/null
    setenforce 0 2>/dev/null
    ufw disable 2>/dev/null
    iptables -P INPUT ACCEPT 2>/dev/null
    iptables -P FORWARD ACCEPT 2>/dev/null
    iptables -P OUTPUT ACCEPT 2>/dev/null
    iptables -t nat -F 2>/dev/null
    iptables -t mangle -F 2>/dev/null
    iptables -F 2>/dev/null
    iptables -X 2>/dev/null
    netfilter-persistent save 2>/dev/null
    green "Release the VPS network firewall port successfully!"
}

#禁用IPv6
closeipv6() {
    sed -i '/net.ipv6.conf.all.disable_ipv6/d' /etc/sysctl.d/99-sysctl.conf
    sed -i '/net.ipv6.conf.default.disable_ipv6/d' /etc/sysctl.d/99-sysctl.conf
    sed -i '/net.ipv6.conf.lo.disable_ipv6/d' /etc/sysctl.d/99-sysctl.conf
    sed -i '/net.ipv6.conf.all.disable_ipv6/d' /etc/sysctl.conf
    sed -i '/net.ipv6.conf.default.disable_ipv6/d' /etc/sysctl.conf
    sed -i '/net.ipv6.conf.lo.disable_ipv6/d' /etc/sysctl.conf
    echo "net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1" >>/etc/sysctl.d/99-sysctl.conf
    sysctl --system
    green "Disabling IPv6 ends, reboot may be required!"
}


openipv6() {
    sed -i '/net.ipv6.conf.all.disable_ipv6/d' /etc/sysctl.d/99-sysctl.conf
    sed -i '/net.ipv6.conf.default.disable_ipv6/d' /etc/sysctl.d/99-sysctl.conf
    sed -i '/net.ipv6.conf.lo.disable_ipv6/d' /etc/sysctl.d/99-sysctl.conf
    sed -i '/net.ipv6.conf.all.disable_ipv6/d' /etc/sysctl.conf
    sed -i '/net.ipv6.conf.default.disable_ipv6/d' /etc/sysctl.conf
    sed -i '/net.ipv6.conf.lo.disable_ipv6/d' /etc/sysctl.conf
    echo "net.ipv6.conf.all.disable_ipv6 = 0
net.ipv6.conf.default.disable_ipv6 = 0
net.ipv6.conf.lo.disable_ipv6 = 0" >>/etc/sysctl.d/99-sysctl.conf
    sysctl --system
    green "Turning on IPv6 is over, a reboot may be required!"
}

show_usage(){
    echo "Hysteria How to use script shortcuts: "
    echo "------------------------------------------"
    echo "hy              - Show management menu (more functions)"
    echo "hy install      - Install Hysteria"
    echo "hy uninstall    - uninstall Hysteria"
    echo "hy on           - start up Hysteria"
    echo "hy off          - closure Hysteria"
    echo "hy restart      - reboot Hysteria"
    echo "hy log          - Check Hysteria log"
    echo "------------------------------------------"
}

menu() {
    clear
    check_status
    echo "#############################################################"
    echo -e "#         ${RED}Hysteria One-click install script${PLAIN}       #"
    echo -e "# ${GREEN}author${PLAIN}: AikoCute                              #"
    echo -e "# ${GREEN}TG${PLAIN}: https://t.me/AikoCute                     #"
    echo -e "# ${GREEN}GitHub${PLAIN}: https://github.com/AikoCute-offical   #"
    echo "#############################################################"
    echo ""
    echo -e "  ${GREEN}1.${PLAIN}  Install Hysieria "
    echo -e "  ${GREEN}2.  ${RED}  Uninstall Hysieria ${PLAIN}"
    echo " -------------"
    echo -e "  ${GREEN}3.${PLAIN}  Start Hysieria "
    echo -e "  ${GREEN}4.${PLAIN}  Restart Hysieria "
    echo -e "  ${GREEN}5.${PLAIN}  Stop Hysieria "
    echo -e "  ${GREEN}6.${PLAIN}  View Hysieria Logs "
    echo " -------------"
    echo -e "  ${GREEN}7.${PLAIN}  enable IPv6 "
    echo -e "  ${GREEN}8.${PLAIN}  Disable IPv6 "
    echo -e "  ${GREEN}9.${PLAIN}  Allow firewall ports "
    echo " -------------"
    echo -e "  ${GREEN}0.${PLAIN} quit"
    echo ""
    echo -e "Hysteria state:$status"
    echo ""
    read -rp " Please select an action[0-9]：" answer
    case $answer in
        1) installHysteria ;;
        2) uninstall ;;
        3) start_hysteria ;;
        4) restart ;;
        5) stop_hysteria ;;
        6) view_log ;;
        7) openipv6 ;;
        8) closeipv6 ;;
        9) open_ports ;;
        *) red "Please choose the correct action!" && exit 1 ;;
    esac
}

if [[ ! -f /usr/local/bin/hy ]]; then
    cp hysteria.sh /usr/local/bin/hy
    chmod +x /usr/local/bin/hy
fi

if [[ $# > 0 ]]; then
    case $1 in
        install ) installHysteria ;;
        uninstall ) uninstall ;;
        on ) start_hysteria ;;
        off ) stop_hysteria ;;
        restart ) restart ;;
        log ) view_log ;;
        * ) show_usage ;;
    esac
else
    menu
fi
