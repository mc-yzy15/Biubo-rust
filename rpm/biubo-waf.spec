Name:           biubo-waf
Version:        1.0.0
Release:        1%{?dist}
Summary:        A Web Application Firewall that Thinks, Remembers, and Visualizes

License:        MIT
URL:            https://github.com/mc-yzy15/Biubo-rust

BuildRequires:  systemd
Requires:       systemd

%description
Biubo WAF is a Web Application Firewall that provides intelligent protection
with AI-powered threat detection, session replay, and real-time visualization.

%pre
getent passwd biubo >/dev/null || \
    useradd -r -g biubo -d /etc/biubo-waf -s /sbin/nologin \
    -c "Biubo WAF service account" biubo 2>/dev/null || :

%post
systemctl daemon-reload
systemctl enable biubo-waf.service || :

mkdir -p /etc/biubo-waf
mkdir -p /var/lib/biubo-waf
mkdir -p /var/log/biubo-waf

chown -R biubo:biubo /etc/biubo-waf
chown -R biubo:biubo /var/lib/biubo-waf
chown -R biubo:biubo /var/log/biubo-waf

chmod 750 /etc/biubo-waf
chmod 750 /var/lib/biubo-waf
chmod 750 /var/log/biubo-waf

%preun
if [ $1 -eq 0 ]; then
    systemctl stop biubo-waf.service >/dev/null 2>&1 || :
    systemctl disable biubo-waf.service >/dev/null 2>&1 || :
fi

%postun
systemctl daemon-reload

%files
/usr/bin/biubo-waf
/usr/lib/systemd/system/biubo-waf.service
%config /etc/biubo-waf/

%changelog
* Sat May 09 2026 mc-yzy15 <yingmoliuguang@yeah.net> - 1.0.0-1
- Initial package release
